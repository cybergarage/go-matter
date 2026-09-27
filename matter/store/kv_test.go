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
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// kvStoreFactories runs the KVStore conformance tests against every
// implementation.
func kvStoreFactories() map[string]func(t *testing.T) TxKVStore {
	return map[string]func(t *testing.T) TxKVStore{
		"mem": func(*testing.T) TxKVStore { return NewMemKVStore() },
		"file": func(t *testing.T) TxKVStore {
			t.Helper()
			s, err := NewFileKVStore(filepath.Join(t.TempDir(), "kv"))
			if err != nil {
				t.Fatalf("NewFileKVStore(...) error = %v", err)
			}
			return s
		},
	}
}

func TestValidateKey(t *testing.T) {
	valid := []string{"a", "fabric.json", "f/1/noc", "commissions/0000-0001.json", "A_b-c.d"}
	for _, k := range valid {
		if err := ValidateKey(k); err != nil {
			t.Errorf("ValidateKey(%q) = %v, want nil", k, err)
		}
	}
	invalid := []string{"", "/a", "a/", "a//b", ".a", "a/.b", "..", "a/../b", "a b", `a\b`, "a:b"}
	for _, k := range invalid {
		if err := ValidateKey(k); err == nil {
			t.Errorf("ValidateKey(%q) = nil, want an error", k)
		}
	}
}

func TestKVStoreBasics(t *testing.T) {
	for name, newStore := range kvStoreFactories() {
		t.Run(name, func(t *testing.T) {
			s := newStore(t)

			if _, err := s.Get("a"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("Get(missing) error = %v, want ErrNotFound", err)
			}
			if err := s.Set("a", []byte("1")); err != nil {
				t.Fatal(err)
			}
			if err := s.Set("dir/b", []byte("2")); err != nil {
				t.Fatal(err)
			}
			if err := s.Set("dir/sub/c", []byte("3")); err != nil {
				t.Fatal(err)
			}
			if err := s.Set("a", []byte("11")); err != nil {
				t.Fatal(err)
			}
			if got, err := s.Get("a"); err != nil || string(got) != "11" {
				t.Fatalf("Get(a) = (%q, %v), want (11, nil)", got, err)
			}

			got, err := s.Get("dir/b")
			if err != nil {
				t.Fatal(err)
			}
			got[0] = 'x'
			if again, _ := s.Get("dir/b"); string(again) != "2" {
				t.Fatalf("mutating a Get result changed the stored value to %q", again)
			}

			assertKeys(t, s, "", []string{"a", "dir/b", "dir/sub/c"})
			assertKeys(t, s, "dir/", []string{"dir/b", "dir/sub/c"})
			assertKeys(t, s, "nothing/", []string{})

			if err := s.Delete("dir/b"); err != nil {
				t.Fatal(err)
			}
			if err := s.Delete("dir/b"); err != nil {
				t.Fatalf("Delete(missing) error = %v, want nil", err)
			}
			if _, err := s.Get("dir/b"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("Get(deleted) error = %v, want ErrNotFound", err)
			}
			assertKeys(t, s, "", []string{"a", "dir/sub/c"})

			if err := s.Set("../escape", []byte("x")); err == nil {
				t.Fatal("Set(../escape) = nil, want an error")
			}
			if _, err := s.Get(".journal.json"); err == nil {
				t.Fatal("Get(.journal.json) = nil, want an error")
			}
		})
	}
}

func TestKVStoreTxCommit(t *testing.T) {
	for name, newStore := range kvStoreFactories() {
		t.Run(name, func(t *testing.T) {
			s := newStore(t)
			if err := s.Set("keep", []byte("k")); err != nil {
				t.Fatal(err)
			}
			if err := s.Set("drop", []byte("d")); err != nil {
				t.Fatal(err)
			}

			tx, err := s.Begin()
			if err != nil {
				t.Fatal(err)
			}
			if err := tx.Set("new/a", []byte("1")); err != nil {
				t.Fatal(err)
			}
			if err := tx.Set("new/a", []byte("2")); err != nil {
				t.Fatal(err)
			}
			if err := tx.Delete("drop"); err != nil {
				t.Fatal(err)
			}

			// Read-your-writes inside the transaction, invisible outside.
			if got, err := tx.Get("new/a"); err != nil || string(got) != "2" {
				t.Fatalf("tx.Get(new/a) = (%q, %v), want (2, nil)", got, err)
			}
			if _, err := tx.Get("drop"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("tx.Get(drop) error = %v, want ErrNotFound", err)
			}
			if got, err := tx.Get("keep"); err != nil || string(got) != "k" {
				t.Fatalf("tx.Get(keep) = (%q, %v), want (k, nil)", got, err)
			}
			if _, err := s.Get("new/a"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("store sees an uncommitted write: error = %v", err)
			}

			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
			assertKeys(t, s, "", []string{"keep", "new/a"})
			if got, _ := s.Get("new/a"); string(got) != "2" {
				t.Fatalf("Get(new/a) after commit = %q, want 2", got)
			}

			if err := tx.Commit(); !errors.Is(err, ErrTxDone) {
				t.Fatalf("second Commit() error = %v, want ErrTxDone", err)
			}
			if err := tx.Set("x", nil); !errors.Is(err, ErrTxDone) {
				t.Fatalf("Set after Commit error = %v, want ErrTxDone", err)
			}
		})
	}
}

func TestKVStoreTxRollback(t *testing.T) {
	for name, newStore := range kvStoreFactories() {
		t.Run(name, func(t *testing.T) {
			s := newStore(t)
			if err := s.Set("keep", []byte("k")); err != nil {
				t.Fatal(err)
			}
			tx, err := s.Begin()
			if err != nil {
				t.Fatal(err)
			}
			if err := tx.Set("new", []byte("1")); err != nil {
				t.Fatal(err)
			}
			if err := tx.Delete("keep"); err != nil {
				t.Fatal(err)
			}
			if err := tx.Rollback(); err != nil {
				t.Fatal(err)
			}
			assertKeys(t, s, "", []string{"keep"})
			if err := tx.Commit(); !errors.Is(err, ErrTxDone) {
				t.Fatalf("Commit after Rollback error = %v, want ErrTxDone", err)
			}
			if err := tx.Set("bad key/", nil); err == nil {
				t.Fatal("tx.Set(invalid key) = nil, want an error")
			}
		})
	}
}

func TestFileKVStoreLayoutAndPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "kv")
	s, err := NewFileKVStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s.Dir() != dir {
		t.Fatalf("Dir() = %q, want %q", s.Dir(), dir)
	}
	assertPermissions(t, dir, dirMode)
	if err := s.Set("sub/v.json", []byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "sub", "v.json")
	b, err := os.ReadFile(path)
	if err != nil || string(b) != `{"a":1}` {
		t.Fatalf("ReadFile(%s) = (%q, %v), want the raw value", path, b, err)
	}
	assertPermissions(t, path, fileMode)
	assertPermissions(t, filepath.Join(dir, "sub"), dirMode)

	// Leftover temporary files and unrelated dot files are not keys.
	if err := os.WriteFile(filepath.Join(dir, "sub", ".tmp-123"), []byte("x"), fileMode); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, ".hidden"), dirMode); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".hidden", "x"), []byte("x"), fileMode); err != nil {
		t.Fatal(err)
	}
	assertKeys(t, s, "", []string{"sub/v.json"})
}

// TestFileKVStoreRecoversJournal simulates a crash after a transaction's
// journal was written but before it was fully applied.
func TestFileKVStoreRecoversJournal(t *testing.T) {
	dir := t.TempDir()
	s, err := NewFileKVStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Set("old", []byte("o")); err != nil {
		t.Fatal(err)
	}
	if err := s.Set("a", []byte("stale")); err != nil {
		t.Fatal(err)
	}
	journal := `[{"key":"a","value":"MQ=="},{"key":"b/c","value":"Mg=="},{"key":"old","deleted":true}]`
	if err := os.WriteFile(filepath.Join(dir, journalFileName), []byte(journal), fileMode); err != nil {
		t.Fatal(err)
	}

	s, err = NewFileKVStore(dir)
	if err != nil {
		t.Fatalf("NewFileKVStore(...) with a pending journal error = %v", err)
	}
	assertKeys(t, s, "", []string{"a", "b/c"})
	if got, _ := s.Get("a"); string(got) != "1" {
		t.Fatalf("Get(a) = %q, want 1", got)
	}
	if _, err := os.Stat(filepath.Join(dir, journalFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("journal still present after recovery: %v", err)
	}
}

func TestFileKVStoreRejectsCorruptJournal(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, journalFileName), []byte("{"), fileMode); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileKVStore(dir); err == nil {
		t.Fatal("NewFileKVStore(...) with a corrupt journal = nil error, want an error")
	}
}

func assertKeys(t *testing.T, s KVStore, prefix string, want []string) {
	t.Helper()
	got, err := s.List(prefix)
	if err != nil {
		t.Fatalf("List(%q) error = %v", prefix, err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("List(%q) = %v, want %v", prefix, got, want)
	}
}
