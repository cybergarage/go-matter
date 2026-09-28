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
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

const (
	// dirMode and fileMode are deliberately restrictive: the values a
	// Matter node persists include private key material in plaintext.
	dirMode  = 0o700
	fileMode = 0o600

	tmpFilePattern  = ".tmp-*"
	journalFileName = ".journal.json"
)

// FileKVStore is a TxKVStore that keeps one file per key under a base
// directory: the key "commissions/a.json" is the file
// <dir>/commissions/a.json. Values are written as they are given, so a
// JSON value stays a human-readable JSON file.
//
// Each Set writes a temporary file and renames it over the target, so a
// crash never leaves a half-written value. A transaction is made atomic
// with a journal: Commit first writes every pending write to
// <dir>/.journal.json, then applies them, then removes the journal, and
// NewFileKVStore replays a journal left behind by a crash.
//
// A FileKVStore is safe for concurrent use within one process, but two
// processes must not open the same directory at the same time.
type FileKVStore struct {
	mu  sync.RWMutex
	dir string
}

// NewFileKVStore returns a FileKVStore rooted at dir, creating dir (at
// 0700) if it does not exist and completing any transaction a previous
// process committed but did not finish applying.
func NewFileKVStore(dir string) (*FileKVStore, error) {
	if dir == "" {
		return nil, fmt.Errorf("store: directory is required")
	}
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return nil, fmt.Errorf("store: create %s: %w", dir, err)
	}
	s := &FileKVStore{mu: sync.RWMutex{}, dir: dir}
	if err := s.recoverJournal(); err != nil {
		return nil, err
	}
	return s, nil
}

// Dir returns the base directory this store reads from and writes to.
func (s *FileKVStore) Dir() string {
	return s.dir
}

func (s *FileKVStore) path(key string) string {
	return filepath.Join(s.dir, filepath.FromSlash(key))
}

// Get implements KVStore.
func (s *FileKVStore) Get(key string) ([]byte, error) {
	if err := ValidateKey(key); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.get(key)
}

func (s *FileKVStore) get(key string) ([]byte, error) {
	b, err := os.ReadFile(s.path(key))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, notFound(key)
		}
		return nil, fmt.Errorf("store: read %s: %w", key, err)
	}
	return b, nil
}

// Set implements KVStore.
func (s *FileKVStore) Set(key string, value []byte) error {
	if err := ValidateKey(key); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.set(key, value)
}

func (s *FileKVStore) set(key string, value []byte) error {
	return writeFileAtomic(s.path(key), value)
}

// Delete implements KVStore.
func (s *FileKVStore) Delete(key string) error {
	if err := ValidateKey(key); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.delete(key)
}

func (s *FileKVStore) delete(key string) error {
	if err := os.Remove(s.path(key)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("store: delete %s: %w", key, err)
	}
	return nil
}

// List implements KVStore. Files and directories whose names start with
// '.' (the store's own temporary files and journal), and any file whose
// path is not a valid key, are skipped.
func (s *FileKVStore) List(prefix string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	keys := []string{}
	err := filepath.WalkDir(s.dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == s.dir {
			return nil
		}
		if strings.HasPrefix(d.Name(), ".") {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(s.dir, path)
		if err != nil {
			return err
		}
		key := filepath.ToSlash(rel)
		if isValidKey(key) && strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("store: list %s: %w", s.dir, err)
	}
	sort.Strings(keys)
	return keys, nil
}

// Begin implements TxKVStore.
func (s *FileKVStore) Begin() (Tx, error) {
	return &fileTx{store: s, buf: newTxBuffer()}, nil
}

func (s *FileKVStore) journalPath() string {
	return filepath.Join(s.dir, journalFileName)
}

// apply writes every op of a committed transaction. Every op is a full
// overwrite or a delete, so replaying the same ops after a crash midway
// yields the same result.
func (s *FileKVStore) apply(ops []txOp) error {
	for _, op := range ops {
		if err := ValidateKey(op.Key); err != nil {
			return err
		}
		var err error
		if op.Deleted {
			err = s.delete(op.Key)
		} else {
			err = s.set(op.Key, op.Value)
		}
		if err != nil {
			return err
		}
	}
	if err := os.Remove(s.journalPath()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("store: remove journal: %w", err)
	}
	return nil
}

func (s *FileKVStore) recoverJournal() error {
	b, err := os.ReadFile(s.journalPath())
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("store: read journal: %w", err)
	}
	var ops []txOp
	if err := json.Unmarshal(b, &ops); err != nil {
		return fmt.Errorf("store: parse journal: %w", err)
	}
	return s.apply(ops)
}

type fileTx struct {
	store *FileKVStore
	buf   *txBuffer
}

func (tx *fileTx) Get(key string) ([]byte, error) {
	return tx.buf.get(key, tx.store.Get)
}

func (tx *fileTx) Set(key string, value []byte) error {
	return tx.buf.put(txOp{Key: key, Value: append([]byte{}, value...), Deleted: false})
}

func (tx *fileTx) Delete(key string) error {
	return tx.buf.put(txOp{Key: key, Value: nil, Deleted: true})
}

func (tx *fileTx) Commit() error {
	if tx.buf.done {
		return ErrTxDone
	}
	tx.buf.done = true
	if len(tx.buf.ops) == 0 {
		return nil
	}
	s := tx.store
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := json.Marshal(tx.buf.ops)
	if err != nil {
		return fmt.Errorf("store: encode journal: %w", err)
	}
	// Once the journal is durably in place the transaction is committed:
	// a crash from here on is completed by recoverJournal.
	if err := writeFileAtomic(s.journalPath(), b); err != nil {
		return err
	}
	return s.apply(tx.buf.ops)
}

func (tx *fileTx) Rollback() error {
	if tx.buf.done {
		return ErrTxDone
	}
	tx.buf.done = true
	return nil
}

// writeFileAtomic writes b to path by writing a temporary file in the same
// directory, syncing it, and renaming it over path.
func writeFileAtomic(path string, b []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return fmt.Errorf("store: create %s: %w", dir, err)
	}
	f, err := os.CreateTemp(dir, tmpFilePattern)
	if err != nil {
		return fmt.Errorf("store: create temporary file in %s: %w", dir, err)
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	if err := f.Chmod(fileMode); err != nil {
		return fmt.Errorf("store: chmod %s: %w", tmp, err)
	}
	if _, err := f.Write(b); err != nil {
		return fmt.Errorf("store: write %s: %w", tmp, err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("store: sync %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("store: close %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("store: rename %s: %w", path, err)
	}
	ok = true
	syncDir(dir)
	return nil
}

// syncDir makes a rename in dir durable. It is best effort: some platforms
// (Windows) cannot open a directory for syncing.
func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}
