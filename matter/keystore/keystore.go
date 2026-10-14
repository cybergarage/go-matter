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

// Package keystore keeps the private keys of a Matter node apart from the
// rest of its state, such as the root CA key a commissioner issues NOCs
// with and the operational key it runs CASE with (6.5. Node Operational
// Credentials).
//
// A key is used through crypto.Signer, the interface PKCS#11, cloud KMS
// and TPM libraries give their keys through, so a KeyStore can be backed by
// hardware which never hands the private key out. The package provides an
// in-memory store, a file store which encrypts its keys with a passphrase,
// and a store of signers made elsewhere.
package keystore

import (
	"crypto"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"regexp"
)

var (
	// ErrKeyNotFound is returned for a key the store does not have.
	ErrKeyNotFound = errors.New("keystore: key not found")
	// ErrKeyExists is returned when a key to generate or import is there
	// already.
	ErrKeyExists = errors.New("keystore: key already exists")
	// ErrInvalidKeyName is returned for a name which is not a key name.
	ErrInvalidKeyName = errors.New("keystore: invalid key name")
)

// KeyStore keeps named P-256 keys and signs with them.
type KeyStore interface {
	// Signer returns the key named name, or an error which wraps
	// ErrKeyNotFound.
	Signer(name string) (crypto.Signer, error)
	// Generate creates a P-256 key named name and returns it, or an error
	// which wraps ErrKeyExists when there is one.
	Generate(name string) (crypto.Signer, error)
	// Delete removes the key named name, or returns an error which wraps
	// ErrKeyNotFound.
	Delete(name string) error
}

// Importer is a KeyStore which takes in a key made elsewhere, such as one
// moved from an older store.
type Importer interface {
	// Import keeps key under name, or returns an error which wraps
	// ErrKeyExists when there is a key under it.
	Import(name string, key *ecdsa.PrivateKey) error
}

var keyNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// ValidateKeyName checks that name is a key name: 1 to 64 lowercase
// letters, digits, '.', '_' and '-', starting with a letter or a digit, so
// that it is a file name as well.
func ValidateKeyName(name string) error {
	if !keyNamePattern.MatchString(name) {
		return fmt.Errorf("%w: %q", ErrInvalidKeyName, name)
	}
	return nil
}
