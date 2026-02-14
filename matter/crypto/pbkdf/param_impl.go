// Copyright (C) 2025 The go-matter Authors. All rights reserved.
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

package pbkdf

import (
	"crypto/sha256"
	"hash"
)

// PBKDFParamRequest/Response fields are defined by the Matter specification using
// context-specific tag numbers.
const (
	pbkdfTagIterations = 1
	pbkdfTagSalt       = 2
)

// ParamsOption defines a functional option for configuring PBKDF parameters.
type ParamsOption func(*params)

// WithParamsPassword sets the password (e.g., the pairing code) for PBKDF key derivation.
func WithParamsPassword(password []byte) ParamsOption {
	return func(p *params) {
		p.password = password
	}
}

// WithParamsSalt sets the salt value for PBKDF key derivation.
func WithParamsSalt(salt []byte) ParamsOption {
	return func(p *params) {
		p.salt = salt
	}
}

// WithParamsIterations sets the number of iterations for PBKDF key derivation.
func WithParamsIterations(iter int) ParamsOption {
	return func(p *params) {
		p.iter = iter
	}
}

// WithParamsKeyLength sets the key length for PBKDF key derivation.
func WithParamsKeyLength(keyLen int) ParamsOption {
	return func(p *params) {
		p.keyLen = keyLen
	}
}

// WithParamsHash sets the hash function for PBKDF key derivation.
func WithParamsHash(hashFunc func() hash.Hash) ParamsOption {
	return func(p *params) {
		p.hash = hashFunc
	}
}

type params struct {
	password []byte
	salt     []byte
	iter     int
	keyLen   int
	hash     func() hash.Hash
}

// NewParams creates a new Params instance with the provided options.
func NewParams(opts ...ParamsOption) Params {
	p := &params{
		password: nil,        // Default password (should be set by caller)
		salt:     nil,        // Default salt (should be set by caller)
		iter:     100000,     // Default iteration count
		keyLen:   32,         // Default key length (e.g., 256 bits)
		hash:     sha256.New, // Default hash function
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

func (p *params) Password() []byte {
	return p.password
}

func (p *params) Salt() []byte {
	return p.salt
}

func (p *params) Iterations() int {
	return p.iter
}

func (p *params) KeyLength() int {
	return p.keyLen
}

func (p *params) Hash() hash.Hash {
	return p.hash()
}
