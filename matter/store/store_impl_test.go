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
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestNewStoreCreatesDirectories(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "app")
	s, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore(...) error = %v", err)
	}
	assertPermissions(t, dir, dirMode)
	if err := s.SaveCommissionee(CommissioneeRecord{NodeID: 1, CompressedFabricID: 1}); err != nil {
		t.Fatal(err)
	}
	assertPermissions(t, filepath.Join(dir, commissioneesDirName), dirMode)
}

func TestFabricRecordRoundTrip(t *testing.T) {
	s, dir := newTestStore(t)

	if _, ok, err := s.LoadFabric(); err != nil || ok {
		t.Fatalf("LoadFabric() before save = (_, %v, %v), want (_, false, nil)", ok, err)
	}

	want := FabricRecord{
		FabricID:        2,
		AdminNodeID:     1,
		AdminVendorID:   0xFFF1,
		RootCertificate: []byte("root-cert"),
		RootPrivateKey:  []byte("root-key"),
		NOC:             []byte("admin-noc"),
		PrivateKey:      []byte("admin-key"),
		IPK:             []byte("0123456789abcdef"),
		UpdatedAt:       time.Now().UTC().Truncate(time.Second),
	}
	if err := s.SaveFabric(want); err != nil {
		t.Fatalf("SaveFabric(...) error = %v", err)
	}
	assertPermissions(t, filepath.Join(dir, fabricKey), fileMode)

	got, ok, err := s.LoadFabric()
	if err != nil || !ok {
		t.Fatalf("LoadFabric() after save = (_, %v, %v), want (_, true, nil)", ok, err)
	}
	if got.FabricID != want.FabricID || got.AdminNodeID != want.AdminNodeID ||
		got.AdminVendorID != want.AdminVendorID || string(got.RootCertificate) != string(want.RootCertificate) ||
		string(got.RootPrivateKey) != string(want.RootPrivateKey) || string(got.NOC) != string(want.NOC) ||
		string(got.PrivateKey) != string(want.PrivateKey) || string(got.IPK) != string(want.IPK) ||
		!got.UpdatedAt.Equal(want.UpdatedAt) {
		t.Fatalf("LoadFabric() = %+v, want %+v", got, want)
	}
}

func TestCommissioneeRecordRoundTrip(t *testing.T) {
	s, dir := newTestStore(t)

	if _, ok, err := s.LoadCommissionee(0x1111, 0x2222); err != nil || ok {
		t.Fatalf("LoadCommissionee(...) before save = (_, %v, %v), want (_, false, nil)", ok, err)
	}

	want := CommissioneeRecord{
		NodeID:             0x2222,
		FabricID:           2,
		CompressedFabricID: 0x1111,
		VendorID:           0xFFF1,
		ProductID:          0x8000,
		Discriminator:      0x0F00,
		NOC:                []byte("device-noc"),
		CommissionedAt:     time.Now().UTC().Truncate(time.Second),
	}
	if err := s.SaveCommissionee(want); err != nil {
		t.Fatalf("SaveCommissionee(...) error = %v", err)
	}

	wantPath := filepath.Join(dir, commissioneesDirName, "0000000000001111-0000000000002222.json")
	assertPermissions(t, wantPath, fileMode)

	got, ok, err := s.LoadCommissionee(0x1111, 0x2222)
	if err != nil || !ok {
		t.Fatalf("LoadCommissionee(...) after save = (_, %v, %v), want (_, true, nil)", ok, err)
	}
	if got.NodeID != want.NodeID || got.FabricID != want.FabricID ||
		got.CompressedFabricID != want.CompressedFabricID || got.VendorID != want.VendorID ||
		got.ProductID != want.ProductID || got.Discriminator != want.Discriminator ||
		string(got.NOC) != string(want.NOC) || !got.CommissionedAt.Equal(want.CommissionedAt) {
		t.Fatalf("LoadCommissionee(...) = %+v, want %+v", got, want)
	}
}

func TestListCommissionees(t *testing.T) {
	for name, s := range testStores(t) {
		t.Run(name, func(t *testing.T) { testListCommissionees(t, s) })
	}
}

func testListCommissionees(t *testing.T, s Store) {
	t.Helper()

	if recs, err := s.ListCommissionees(); err != nil || len(recs) != 0 {
		t.Fatalf("ListCommissionees() before save = (%v, %v), want (empty, nil)", recs, err)
	}

	recA := CommissioneeRecord{NodeID: 1, CompressedFabricID: 0xA}
	recB := CommissioneeRecord{NodeID: 2, CompressedFabricID: 0xB}
	if err := s.SaveCommissionee(recA); err != nil {
		t.Fatalf("SaveCommissionee(recA) error = %v", err)
	}
	if err := s.SaveCommissionee(recB); err != nil {
		t.Fatalf("SaveCommissionee(recB) error = %v", err)
	}

	recs, err := s.ListCommissionees()
	if err != nil {
		t.Fatalf("ListCommissionees() error = %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("len(ListCommissionees()) = %d, want 2", len(recs))
	}
	gotNodeIDs := map[uint64]bool{}
	for _, rec := range recs {
		gotNodeIDs[rec.NodeID] = true
	}
	if !gotNodeIDs[1] || !gotNodeIDs[2] {
		t.Fatalf("ListCommissionees() node IDs = %v, want {1, 2}", gotNodeIDs)
	}
}

func TestDeleteCommissionee(t *testing.T) {
	for name, s := range testStores(t) {
		t.Run(name, func(t *testing.T) {
			if err := s.SaveCommissionee(CommissioneeRecord{NodeID: 2, CompressedFabricID: 0xA}); err != nil {
				t.Fatal(err)
			}
			if err := s.DeleteCommissionee(0xA, 2); err != nil {
				t.Fatalf("DeleteCommissionee(...) error = %v", err)
			}
			if _, ok, err := s.LoadCommissionee(0xA, 2); err != nil || ok {
				t.Fatalf("LoadCommissionee(...) after delete = (_, %v, %v), want (_, false, nil)", ok, err)
			}
			if err := s.DeleteCommissionee(0xA, 2); err != nil {
				t.Fatalf("DeleteCommissionee(missing) error = %v, want nil", err)
			}
		})
	}
}

// TestNewStoreReadsExistingLayout guards the on-disk format: a directory
// written by an earlier release, which wrote fabric.json and
// commissions/*.json directly, must still load.
func TestNewStoreReadsExistingLayout(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, commissioneesDirName), dirMode); err != nil {
		t.Fatal(err)
	}
	fabric := `{"fabricId": 2, "adminNodeId": 1, "adminVendorId": 65521, "ipk": "AAECAwQFBgcICQoLDA0ODw=="}`
	if err := os.WriteFile(filepath.Join(dir, "fabric.json"), []byte(fabric), fileMode); err != nil {
		t.Fatal(err)
	}
	node := `{"nodeId": 34, "fabricId": 2, "compressedFabricId": 17, "vendorId": 65521}`
	if err := os.WriteFile(filepath.Join(dir, commissioneesDirName, "0000000000000011-0000000000000022.json"), []byte(node), fileMode); err != nil {
		t.Fatal(err)
	}
	// Files that are not records are ignored.
	if err := os.WriteFile(filepath.Join(dir, commissioneesDirName, "README"), []byte("x"), fileMode); err != nil {
		t.Fatal(err)
	}

	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	f, ok, err := s.LoadFabric()
	if err != nil || !ok || f.FabricID != 2 || f.AdminNodeID != 1 || len(f.IPK) != 16 {
		t.Fatalf("LoadFabric() = (%+v, %v, %v), want the existing record", f, ok, err)
	}
	rec, ok, err := s.LoadCommissionee(0x11, 0x22)
	if err != nil || !ok || rec.NodeID != 34 {
		t.Fatalf("LoadCommissionee(...) = (%+v, %v, %v), want the existing record", rec, ok, err)
	}
	recs, err := s.ListCommissionees()
	if err != nil || len(recs) != 1 {
		t.Fatalf("ListCommissionees() = (%v, %v), want 1 record", recs, err)
	}
}

func TestMemStoreRoundTrip(t *testing.T) {
	s := NewMemStore()
	if _, ok, err := s.LoadFabric(); err != nil || ok {
		t.Fatalf("LoadFabric() on an empty store = (_, %v, %v), want (_, false, nil)", ok, err)
	}
	if err := s.SaveFabric(FabricRecord{FabricID: 7}); err != nil {
		t.Fatal(err)
	}
	if rec, ok, err := s.LoadFabric(); err != nil || !ok || rec.FabricID != 7 {
		t.Fatalf("LoadFabric() = (%+v, %v, %v), want FabricID 7", rec, ok, err)
	}
}

func newTestStore(t *testing.T) (Store, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore(...) error = %v", err)
	}
	return s, dir
}

func testStores(t *testing.T) map[string]Store {
	t.Helper()
	s, _ := newTestStore(t)
	return map[string]Store{"file": s, "mem": NewMemStore()}
}

func assertPermissions(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%q) error = %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("Stat(%q).Mode().Perm() = %o, want %o", path, got, want)
	}
}
