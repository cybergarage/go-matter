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

package keystore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
)

// MemKeyStore keeps keys in memory, for tests and for keys which need not
// outlive the process.
type MemKeyStore struct {
	mutex sync.Mutex
	keys  map[string]*ecdsa.PrivateKey
}

// NewMemKeyStore returns an empty MemKeyStore.
func NewMemKeyStore() *MemKeyStore {
	return &MemKeyStore{mutex: sync.Mutex{}, keys: map[string]*ecdsa.PrivateKey{}}
}

// Signer returns the key named name.
func (s *MemKeyStore) Signer(name string) (crypto.Signer, error) {
	if err := ValidateKeyName(name); err != nil {
		return nil, err
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	key, ok := s.keys[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, name)
	}
	return key, nil
}

// Generate creates a P-256 key named name.
func (s *MemKeyStore) Generate(name string) (crypto.Signer, error) {
	key, err := generateKey()
	if err != nil {
		return nil, err
	}
	if err := s.Import(name, key); err != nil {
		return nil, err
	}
	return key, nil
}

// Import keeps key under name.
func (s *MemKeyStore) Import(name string, key *ecdsa.PrivateKey) error {
	if err := ValidateKeyName(name); err != nil {
		return err
	}
	if err := checkKey(key); err != nil {
		return err
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if _, ok := s.keys[name]; ok {
		return fmt.Errorf("%w: %s", ErrKeyExists, name)
	}
	s.keys[name] = key
	return nil
}

// Delete removes the key named name.
func (s *MemKeyStore) Delete(name string) error {
	if err := ValidateKeyName(name); err != nil {
		return err
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if _, ok := s.keys[name]; !ok {
		return fmt.Errorf("%w: %s", ErrKeyNotFound, name)
	}
	delete(s.keys, name)
	return nil
}

func generateKey() (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("keystore: generate a key: %w", err)
	}
	return key, nil
}

func checkKey(key *ecdsa.PrivateKey) error {
	if key == nil || key.Curve != elliptic.P256() {
		return errors.New("keystore: a P-256 key is required")
	}
	return nil
}

var (
	_ KeyStore = (*MemKeyStore)(nil)
	_ Importer = (*MemKeyStore)(nil)
)
