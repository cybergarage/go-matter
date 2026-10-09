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

// The keys below are also file paths relative to a FileKVStore's
// directory, so a Store on a FileKVStore reads and writes exactly the
// layout earlier releases wrote directly.
const (
	fabricKey            = "fabric.json"
	commissioneesDirName = "commissions"
	commissioneeSuffix   = ".json"
	commissioneeKeyFmt   = commissioneesDirName + "/%016X-%016X" + commissioneeSuffix
)

type kvStore struct {
	kv KVStore
}

// NewStore returns a Store that persists to files under dir, creating dir
// (at 0700) if it doesn't already exist. It is NewStoreWithKVStore over a
// FileKVStore rooted at dir.
func NewStore(dir string) (Store, error) {
	kv, err := NewFileKVStore(dir)
	if err != nil {
		return nil, err
	}
	return NewStoreWithKVStore(kv), nil
}

// NewMemStore returns a Store that keeps everything in memory. It is
// meant for tests.
func NewMemStore() Store {
	return NewStoreWithKVStore(NewMemKVStore())
}

// NewStoreWithKVStore returns a Store that persists to kv. Records are
// stored as JSON.
func NewStoreWithKVStore(kv KVStore) Store {
	return &kvStore{kv: kv}
}

// CreateFabric atomically installs a first identity; existing or corrupt records are never replaced.
// Custom stores must implement CreateFabric explicitly; no unsafe load/save fallback is used.
func CreateFabric(st Store, rec FabricRecord) error {
	creator, ok := st.(interface{ CreateFabric(FabricRecord) error })
	if !ok {
		return errors.New("store: atomic fabric creation unsupported")
	}
	return creator.CreateFabric(rec)
}

func (s *kvStore) CreateFabric(rec FabricRecord) error {
	creator, ok := s.kv.(interface{ Create(string, []byte) error })
	if !ok {
		return errors.New("store: atomic creation unsupported by backend")
	}
	// Identity persistence intentionally contains private key material in a protected store.
	b, err := json.MarshalIndent(rec, "", "  ") //nolint:gosec
	if err != nil {
		return err
	}
	return creator.Create(fabricKey, b)
}

func (s *kvStore) SaveFabric(rec FabricRecord) error {
	return s.put(fabricKey, rec)
}

func (s *kvStore) LoadFabric() (FabricRecord, bool, error) {
	var rec FabricRecord
	ok, err := s.load(fabricKey, &rec)
	return rec, ok, err
}

func (s *kvStore) SaveCommissionee(rec CommissioneeRecord) error {
	return s.put(commissioneeKey(rec.CompressedFabricID, rec.NodeID), rec)
}

func (s *kvStore) LoadCommissionee(compressedFabricID, nodeID uint64) (CommissioneeRecord, bool, error) {
	var rec CommissioneeRecord
	ok, err := s.load(commissioneeKey(compressedFabricID, nodeID), &rec)
	return rec, ok, err
}

func (s *kvStore) DeleteCommissionee(compressedFabricID, nodeID uint64) error {
	return s.kv.Delete(commissioneeKey(compressedFabricID, nodeID))
}

func (s *kvStore) ListCommissionees() ([]CommissioneeRecord, error) {
	prefix := commissioneesDirName + "/"
	keys, err := s.kv.List(prefix)
	if err != nil {
		return nil, err
	}
	recs := make([]CommissioneeRecord, 0, len(keys))
	for _, key := range keys {
		name := strings.TrimPrefix(key, prefix)
		if strings.Contains(name, "/") || !strings.HasSuffix(name, commissioneeSuffix) {
			continue
		}
		var rec CommissioneeRecord
		ok, err := s.load(key, &rec)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		recs = append(recs, rec)
	}
	return recs, nil
}

func commissioneeKey(compressedFabricID, nodeID uint64) string {
	return fmt.Sprintf(commissioneeKeyFmt, compressedFabricID, nodeID)
}

func (s *kvStore) put(key string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("store: marshal %s: %w", key, err)
	}
	return s.kv.Set(key, b)
}

// load reads key into v. ok is false, with a nil error, when key is not
// stored.
func (s *kvStore) load(key string, v any) (bool, error) {
	b, err := s.kv.Get(key)
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
