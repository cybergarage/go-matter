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
	"sort"
	"strings"
	"sync"
)

type memKVStore struct {
	mu   sync.RWMutex
	data map[string][]byte
}

// NewMemKVStore returns an in-memory TxKVStore. Nothing survives the
// process; it is meant for tests and for callers that manage persistence
// themselves.
func NewMemKVStore() TxKVStore {
	return &memKVStore{mu: sync.RWMutex{}, data: map[string][]byte{}}
}

func (s *memKVStore) Get(key string) ([]byte, error) {
	if err := ValidateKey(key); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.data[key]
	if !ok {
		return nil, notFound(key)
	}
	return append([]byte(nil), v...), nil
}

func (s *memKVStore) Set(key string, value []byte) error {
	if err := ValidateKey(key); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[key] = append([]byte{}, value...)
	return nil
}

func (s *memKVStore) Delete(key string) error {
	if err := ValidateKey(key); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, key)
	return nil
}

func (s *memKVStore) List(prefix string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	keys := []string{}
	for k := range s.data {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys, nil
}

func (s *memKVStore) Begin() (Tx, error) {
	return &memTx{store: s, buf: newTxBuffer()}, nil
}

type memTx struct {
	store *memKVStore
	buf   *txBuffer
}

func (tx *memTx) Get(key string) ([]byte, error) {
	return tx.buf.get(key, tx.store.Get)
}

func (tx *memTx) Set(key string, value []byte) error {
	return tx.buf.put(txOp{Key: key, Value: append([]byte{}, value...), Deleted: false})
}

func (tx *memTx) Delete(key string) error {
	return tx.buf.put(txOp{Key: key, Value: nil, Deleted: true})
}

func (tx *memTx) Commit() error {
	if tx.buf.done {
		return ErrTxDone
	}
	tx.buf.done = true
	tx.store.mu.Lock()
	defer tx.store.mu.Unlock()
	for _, op := range tx.buf.ops {
		if op.Deleted {
			delete(tx.store.data, op.Key)
		} else {
			tx.store.data[op.Key] = op.Value
		}
	}
	return nil
}

func (tx *memTx) Rollback() error {
	if tx.buf.done {
		return ErrTxDone
	}
	tx.buf.done = true
	return nil
}
