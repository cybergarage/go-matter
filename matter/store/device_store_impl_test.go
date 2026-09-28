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
	"errors"
	"reflect"
	"testing"
	"time"
)

func deviceStores(t *testing.T) map[string]DeviceStore {
	t.Helper()
	kv, err := NewFileKVStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return map[string]DeviceStore{"file": NewDeviceStore(kv), "mem": NewMemDeviceStore()}
}

func testDeviceFabric(index uint8) DeviceFabricRecord {
	return DeviceFabricRecord{
		FabricIndex:   index,
		FabricID:      0x1000 + uint64(index),
		NodeID:        0x2000 + uint64(index),
		VendorID:      0xFFF1,
		RootPublicKey: []byte{0x04, index},
		Label:         "fabric",
		RCAC:          []byte("rcac"),
		NOC:           []byte("noc"),
		PrivateKey:    []byte("key"),
		UpdatedAt:     time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC),
	}
}

func ptr[T any](v T) *T { return &v }

func TestDeviceFabricRoundTripAndList(t *testing.T) {
	for name, s := range deviceStores(t) {
		t.Run(name, func(t *testing.T) {
			if _, ok, err := s.LoadDeviceFabric(1); err != nil || ok {
				t.Fatalf("LoadDeviceFabric(1) on an empty store = (_, %v, %v), want (_, false, nil)", ok, err)
			}
			// Saved out of order, with an index past 0x0F to check the
			// ordering is numeric.
			for _, i := range []uint8{0x10, 2, MaxFabricIndex, 1} {
				if err := s.SaveDeviceFabric(testDeviceFabric(i)); err != nil {
					t.Fatalf("SaveDeviceFabric(%d) error = %v", i, err)
				}
			}
			got, ok, err := s.LoadDeviceFabric(2)
			if err != nil || !ok || !reflect.DeepEqual(got, testDeviceFabric(2)) {
				t.Fatalf("LoadDeviceFabric(2) = (%+v, %v, %v), want the saved record", got, ok, err)
			}
			recs, err := s.ListDeviceFabrics()
			if err != nil {
				t.Fatal(err)
			}
			indexes := make([]uint8, 0, len(recs))
			for _, r := range recs {
				indexes = append(indexes, r.FabricIndex)
			}
			if want := []uint8{1, 2, 0x10, MaxFabricIndex}; !reflect.DeepEqual(indexes, want) {
				t.Fatalf("ListDeviceFabrics() indexes = %v, want %v", indexes, want)
			}
		})
	}
}

func TestDeviceFabricIndexRange(t *testing.T) {
	s := NewMemDeviceStore()
	for _, i := range []uint8{0, 255} {
		if err := s.SaveDeviceFabric(testDeviceFabric(i)); err == nil {
			t.Errorf("SaveDeviceFabric(index %d) = nil, want an error", i)
		}
		if _, err := s.LoadACL(i); err == nil {
			t.Errorf("LoadACL(%d) = nil error, want an error", i)
		}
	}
}

func TestACLRoundTrip(t *testing.T) {
	for name, s := range deviceStores(t) {
		t.Run(name, func(t *testing.T) {
			if entries, err := s.LoadACL(1); err != nil || len(entries) != 0 {
				t.Fatalf("LoadACL(1) on an empty store = (%v, %v), want (empty, nil)", entries, err)
			}
			want := []ACLEntry{
				{Privilege: PrivilegeAdminister, AuthMode: AuthModeCASE, Subjects: []uint64{0x1122}},
				{
					Privilege: PrivilegeOperate,
					AuthMode:  AuthModeGroup,
					Subjects:  []uint64{0x0101},
					Targets: []ACLTarget{
						{Cluster: ptr(uint32(0x0006)), Endpoint: ptr(uint16(1))},
						{DeviceType: ptr(uint32(0x0100))},
					},
				},
			}
			if err := s.SaveACL(1, want); err != nil {
				t.Fatal(err)
			}
			got, err := s.LoadACL(1)
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("LoadACL(1) = (%+v, %v), want %+v", got, err, want)
			}
			if entries, _ := s.LoadACL(2); len(entries) != 0 {
				t.Fatalf("LoadACL(2) = %v, want the ACL of fabric 1 to stay on fabric 1", entries)
			}

			if err := s.SaveACL(1, nil); err != nil {
				t.Fatal(err)
			}
			if entries, err := s.LoadACL(1); err != nil || len(entries) != 0 {
				t.Fatalf("LoadACL(1) after clearing = (%v, %v), want (empty, nil)", entries, err)
			}
		})
	}
}

func TestACLValidation(t *testing.T) {
	s := NewMemDeviceStore()
	bad := [][]ACLEntry{
		{{Privilege: 0, AuthMode: AuthModeCASE}},
		{{Privilege: 6, AuthMode: AuthModeCASE}},
		{{Privilege: PrivilegeView, AuthMode: 0}},
		{{Privilege: PrivilegeView, AuthMode: 4}},
	}
	for _, entries := range bad {
		if err := s.SaveACL(1, entries); err == nil {
			t.Errorf("SaveACL(%+v) = nil, want an error", entries)
		}
	}
}

func TestGroupKeysRoundTrip(t *testing.T) {
	for name, s := range deviceStores(t) {
		t.Run(name, func(t *testing.T) {
			if rec, err := s.LoadGroupKeys(1); err != nil || len(rec.KeySets) != 0 || len(rec.KeyMap) != 0 {
				t.Fatalf("LoadGroupKeys(1) on an empty store = (%+v, %v), want (empty, nil)", rec, err)
			}
			want := GroupKeysRecord{
				KeySets: []GroupKeySet{
					{GroupKeySetID: 0, SecurityPolicy: GroupKeySecurityPolicyTrustFirst, EpochKeys: []EpochKey{{Key: []byte("ipk-0123456789ab"), StartTime: 0}}},
					{GroupKeySetID: 0x01A1, SecurityPolicy: GroupKeySecurityPolicyCacheAndSync, EpochKeys: []EpochKey{
						{Key: []byte("k0"), StartTime: 1}, {Key: []byte("k1"), StartTime: 2}, {Key: []byte("k2"), StartTime: 3},
					}},
				},
				KeyMap: []GroupKeyMapEntry{{GroupID: 0x0101, GroupKeySetID: 0x01A1}},
			}
			if err := s.SaveGroupKeys(1, want); err != nil {
				t.Fatal(err)
			}
			got, err := s.LoadGroupKeys(1)
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("LoadGroupKeys(1) = (%+v, %v), want %+v", got, err, want)
			}
		})
	}
}

func TestGroupKeysValidation(t *testing.T) {
	s := NewMemDeviceStore()
	for _, n := range []int{0, MaxEpochKeys + 1} {
		keys := make([]EpochKey, n)
		rec := GroupKeysRecord{KeySets: []GroupKeySet{{GroupKeySetID: 1, EpochKeys: keys}}}
		if err := s.SaveGroupKeys(1, rec); err == nil {
			t.Errorf("SaveGroupKeys with %d epoch keys = nil, want an error", n)
		}
	}
}

func TestRemoveDeviceFabric(t *testing.T) {
	for name, s := range deviceStores(t) {
		t.Run(name, func(t *testing.T) {
			for _, i := range []uint8{1, 2} {
				if err := s.SaveDeviceFabric(testDeviceFabric(i)); err != nil {
					t.Fatal(err)
				}
				if err := s.SaveACL(i, []ACLEntry{{Privilege: PrivilegeAdminister, AuthMode: AuthModeCASE}}); err != nil {
					t.Fatal(err)
				}
				if err := s.SaveGroupKeys(i, GroupKeysRecord{KeyMap: []GroupKeyMapEntry{{GroupID: 1, GroupKeySetID: 1}}}); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.RemoveDeviceFabric(1); err != nil {
				t.Fatal(err)
			}
			if err := s.RemoveDeviceFabric(1); err != nil {
				t.Fatalf("RemoveDeviceFabric(missing) error = %v, want nil", err)
			}
			if _, ok, _ := s.LoadDeviceFabric(1); ok {
				t.Error("fabric 1 still present after RemoveDeviceFabric(1)")
			}
			if entries, _ := s.LoadACL(1); len(entries) != 0 {
				t.Error("ACL of fabric 1 still present after RemoveDeviceFabric(1)")
			}
			if rec, _ := s.LoadGroupKeys(1); len(rec.KeyMap) != 0 {
				t.Error("group keys of fabric 1 still present after RemoveDeviceFabric(1)")
			}
			if _, ok, _ := s.LoadDeviceFabric(2); !ok {
				t.Error("RemoveDeviceFabric(1) removed fabric 2")
			}
			if entries, _ := s.LoadACL(2); len(entries) != 1 {
				t.Error("RemoveDeviceFabric(1) removed the ACL of fabric 2")
			}
		})
	}
}

// TestDeviceStoreFailSafe walks through the fail-safe: what AddNOC and the
// ACL write stage is visible inside the transaction only, and is either
// committed on CommissioningComplete or dropped when the fail-safe
// expires.
func TestDeviceStoreFailSafe(t *testing.T) {
	stage := func(t *testing.T, s DeviceStore) DeviceStoreTx {
		t.Helper()
		tx, err := s.Begin()
		if err != nil {
			t.Fatal(err)
		}
		if err := tx.SaveDeviceFabric(testDeviceFabric(1)); err != nil {
			t.Fatal(err)
		}
		if err := tx.SaveACL(1, []ACLEntry{{Privilege: PrivilegeAdminister, AuthMode: AuthModeCASE, Subjects: []uint64{1}}}); err != nil {
			t.Fatal(err)
		}
		if _, ok, err := tx.LoadDeviceFabric(1); err != nil || !ok {
			t.Fatalf("tx.LoadDeviceFabric(1) = (_, %v, %v), want the staged fabric", ok, err)
		}
		if _, ok, _ := s.LoadDeviceFabric(1); ok {
			t.Fatal("the store sees a fabric the fail-safe has not committed")
		}
		return tx
	}

	for name, s := range deviceStores(t) {
		t.Run(name+"/expired", func(t *testing.T) {
			if err := stage(t, s).Rollback(); err != nil {
				t.Fatal(err)
			}
			if recs, _ := s.ListDeviceFabrics(); len(recs) != 0 {
				t.Fatalf("ListDeviceFabrics() after rollback = %v, want none", recs)
			}
			if entries, _ := s.LoadACL(1); len(entries) != 0 {
				t.Fatalf("LoadACL(1) after rollback = %v, want none", entries)
			}
		})
		t.Run(name+"/completed", func(t *testing.T) {
			tx := stage(t, s)
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
			if _, ok, _ := s.LoadDeviceFabric(1); !ok {
				t.Fatal("fabric missing after commit")
			}
			if entries, _ := s.LoadACL(1); len(entries) != 1 {
				t.Fatalf("LoadACL(1) after commit = %v, want 1 entry", entries)
			}
			if err := tx.Commit(); !errors.Is(err, ErrTxDone) {
				t.Fatalf("second Commit() error = %v, want ErrTxDone", err)
			}
		})
	}
}

func TestDeviceStoreCounter(t *testing.T) {
	kv := NewMemKVStore()
	s := NewDeviceStore(kv)
	c, err := s.Counter("boot-count", 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if v, err := c.Next(); err != nil || v != 0 {
		t.Fatalf("Next() = (%d, %v), want (0, nil)", v, err)
	}
	if _, err := kv.Get(deviceCountersPrefix + "boot-count"); err != nil {
		t.Fatalf("counter not stored under %s: %v", deviceCountersPrefix, err)
	}
	if _, err := s.Counter("a/b", 1, 0); err == nil {
		t.Error("Counter(a/b) = nil error, want an error")
	}
}

// TestDeviceAndControllerShareKVStore checks that a device and a
// commissioner can keep their state in one KVStore without seeing each
// other's records.
func TestDeviceAndControllerShareKVStore(t *testing.T) {
	kv, err := NewFileKVStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dev := NewDeviceStore(kv)
	ctl := NewStoreWithKVStore(kv)
	if err := dev.SaveDeviceFabric(testDeviceFabric(1)); err != nil {
		t.Fatal(err)
	}
	if err := ctl.SaveCommissionee(CommissioneeRecord{NodeID: 1, CompressedFabricID: 1}); err != nil {
		t.Fatal(err)
	}
	if recs, err := ctl.ListCommissionees(); err != nil || len(recs) != 1 {
		t.Fatalf("ListCommissionees() = (%v, %v), want 1 record", recs, err)
	}
	if recs, err := dev.ListDeviceFabrics(); err != nil || len(recs) != 1 {
		t.Fatalf("ListDeviceFabrics() = (%v, %v), want 1 record", recs, err)
	}
}
