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
	"errors"
	"fmt"
	"maps"
)

// StaticKeyStore hands out signers made elsewhere, such as the keys of an
// HSM opened with a PKCS#11 library, of a cloud KMS or of a TPM, under the
// names the application gives them. It neither generates nor deletes keys:
// they are made and removed with the tools of where they live.
type StaticKeyStore struct {
	signers map[string]crypto.Signer
}

// NewStaticKeyStore returns a StaticKeyStore of signers by name.
func NewStaticKeyStore(signers map[string]crypto.Signer) (*StaticKeyStore, error) {
	for name, s := range signers {
		if err := ValidateKeyName(name); err != nil {
			return nil, err
		}
		if s == nil {
			return nil, fmt.Errorf("keystore: no signer for %s", name)
		}
	}
	return &StaticKeyStore{signers: maps.Clone(signers)}, nil
}

// Signer returns the signer named name.
func (s *StaticKeyStore) Signer(name string) (crypto.Signer, error) {
	signer, ok := s.signers[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, name)
	}
	return signer, nil
}

// Generate is not supported: the keys are made where they live.
func (s *StaticKeyStore) Generate(name string) (crypto.Signer, error) {
	return nil, fmt.Errorf("keystore: generate %s: %w", name, errors.ErrUnsupported)
}

// Delete is not supported: the keys are removed where they live.
func (s *StaticKeyStore) Delete(name string) error {
	return fmt.Errorf("keystore: delete %s: %w", name, errors.ErrUnsupported)
}

var _ KeyStore = (*StaticKeyStore)(nil)
