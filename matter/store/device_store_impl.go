// Copyright (C) 2026 The go-matter Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Every device key lives under deviceKeyPrefix, so a device and a
// commissioner can share one KVStore. Each fabric's records sit under
// their own prefix so RemoveDeviceFabric is a fixed set of deletes.
const (
	deviceKeyPrefix         = "device/"
	deviceFabricsPrefix     = deviceKeyPrefix + "fabrics/"
	deviceCountersPrefix    = deviceKeyPrefix + "counters/"
	deviceFabricKeyName     = "fabric.json"
	deviceACLKeyName        = "acl.json"
	deviceGroupKeysKeyName  = "groupkeys.json"
	deviceFabricIndexLayout = "%02X"
)

// kvReadWriter is what both a KVStore and a Tx offer, so the record
// encoding below serves the store and its transactions alike.
type kvReadWriter interface {
	Get(key string) ([]byte, error)
	Set(key string, value []byte) error
	Delete(key string) error
}

type deviceStore struct {
	deviceRecords
	kv TxKVStore
}

// NewDeviceStore returns a DeviceStore that persists to kv. kv must be a
// TxKVStore, since a fail-safe's changes are committed or rolled back as
// one.
func NewDeviceStore(kv TxKVStore) DeviceStore {
	return &deviceStore{deviceRecords: deviceRecords{kv: kv}, kv: kv}
}

// NewMemDeviceStore returns a DeviceStore that keeps everything in memory.
// It is meant for tests.
func NewMemDeviceStore() DeviceStore {
	return NewDeviceStore(NewMemKVStore())
}

func (s *deviceStore) ListDeviceFabrics() ([]DeviceFabricRecord, error) {
	keys, err := s.kv.List(deviceFabricsPrefix)
	if err != nil {
		return nil, err
	}
	recs := []DeviceFabricRecord{}
	for _, key := range keys {
		rest := strings.TrimPrefix(key, deviceFabricsPrefix)
		dir, name, found := strings.Cut(rest, "/")
		if !found || name != deviceFabricKeyName {
			continue
		}
		var index uint8
		if _, err := fmt.Sscanf(dir, deviceFabricIndexLayout, &index); err != nil || deviceFabricDir(index) != dir {
			continue
		}
		rec, ok, err := s.LoadDeviceFabric(index)
		if err != nil {
			return nil, err
		}
		if ok {
			recs = append(recs, rec)
		}
	}
	// Keys are sorted and the index is fixed-width hex, so recs is already
	// ordered by fabric index.
	return recs, nil
}

func (s *deviceStore) Begin() (DeviceStoreTx, error) {
	tx, err := s.kv.Begin()
	if err != nil {
		return nil, err
	}
	return &deviceStoreTx{deviceRecords: deviceRecords{kv: tx}, tx: tx}, nil
}

func (s *deviceStore) Counter(name string, reserve, initial uint32) (*PersistentCounter, error) {
	if strings.Contains(name, "/") {
		return nil, fmt.Errorf("store: counter name %q must not contain '/'", name)
	}
	return NewPersistentCounter(s.kv, deviceCountersPrefix+name, reserve, initial)
}

type deviceStoreTx struct {
	deviceRecords
	tx Tx
}

func (t *deviceStoreTx) Commit() error {
	return t.tx.Commit()
}

func (t *deviceStoreTx) Rollback() error {
	return t.tx.Rollback()
}

// deviceRecords encodes the per-fabric records as JSON onto a KVStore or a
// Tx.
type deviceRecords struct {
	kv kvReadWriter
}

func (r deviceRecords) LoadDeviceFabric(fabricIndex uint8) (DeviceFabricRecord, bool, error) {
	var rec DeviceFabricRecord
	key, err := deviceFabricKey(fabricIndex, deviceFabricKeyName)
	if err != nil {
		return rec, false, err
	}
	ok, err := r.load(key, &rec)
	return rec, ok, err
}

func (r deviceRecords) LoadACL(fabricIndex uint8) ([]ACLEntry, error) {
	entries := []ACLEntry{}
	key, err := deviceFabricKey(fabricIndex, deviceACLKeyName)
	if err != nil {
		return nil, err
	}
	if _, err := r.load(key, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func (r deviceRecords) LoadGroupKeys(fabricIndex uint8) (GroupKeysRecord, error) {
	var rec GroupKeysRecord
	key, err := deviceFabricKey(fabricIndex, deviceGroupKeysKeyName)
	if err != nil {
		return rec, err
	}
	_, err = r.load(key, &rec)
	return rec, err
}

func (r deviceRecords) SaveDeviceFabric(rec DeviceFabricRecord) error {
	key, err := deviceFabricKey(rec.FabricIndex, deviceFabricKeyName)
	if err != nil {
		return err
	}
	return r.put(key, rec)
}

func (r deviceRecords) SaveACL(fabricIndex uint8, entries []ACLEntry) error {
	key, err := deviceFabricKey(fabricIndex, deviceACLKeyName)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return r.kv.Delete(key)
	}
	for i, e := range entries {
		if err := validateACLEntry(e); err != nil {
			return fmt.Errorf("store: ACL entry %d: %w", i, err)
		}
	}
	return r.put(key, entries)
}

func (r deviceRecords) SaveGroupKeys(fabricIndex uint8, rec GroupKeysRecord) error {
	key, err := deviceFabricKey(fabricIndex, deviceGroupKeysKeyName)
	if err != nil {
		return err
	}
	for _, set := range rec.KeySets {
		if n := len(set.EpochKeys); n == 0 || n > MaxEpochKeys {
			return fmt.Errorf("store: group key set %d has %d epoch keys, want 1..%d", set.GroupKeySetID, n, MaxEpochKeys)
		}
	}
	return r.put(key, rec)
}

func (r deviceRecords) RemoveDeviceFabric(fabricIndex uint8) error {
	for _, name := range []string{deviceACLKeyName, deviceGroupKeysKeyName, deviceFabricKeyName} {
		key, err := deviceFabricKey(fabricIndex, name)
		if err != nil {
			return err
		}
		if err := r.kv.Delete(key); err != nil {
			return err
		}
	}
	return nil
}

func (r deviceRecords) put(key string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("store: marshal %s: %w", key, err)
	}
	return r.kv.Set(key, b)
}

func (r deviceRecords) load(key string, v any) (bool, error) {
	b, err := r.kv.Get(key)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return false, fmt.Errorf("store: unmarshal %s: %w", key, err)
	}
	return true, nil
}

func deviceFabricDir(fabricIndex uint8) string {
	return fmt.Sprintf(deviceFabricIndexLayout, fabricIndex)
}

func deviceFabricKey(fabricIndex uint8, name string) (string, error) {
	if fabricIndex < MinFabricIndex || fabricIndex > MaxFabricIndex {
		return "", fmt.Errorf("store: fabric index %d out of range %d..%d", fabricIndex, MinFabricIndex, MaxFabricIndex)
	}
	return deviceFabricsPrefix + deviceFabricDir(fabricIndex) + "/" + name, nil
}

func validateACLEntry(e ACLEntry) error {
	if e.Privilege < PrivilegeView || e.Privilege > PrivilegeAdminister {
		return fmt.Errorf("invalid privilege %d", e.Privilege)
	}
	if e.AuthMode < AuthModePASE || e.AuthMode > AuthModeGroup {
		return fmt.Errorf("invalid auth mode %d", e.AuthMode)
	}
	return nil
}
