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

	"github.com/cybergarage/go-matter/matter/encoding/json"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
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
		p.iter = &iter
	}
}

// WithParamsKeyLength sets the key length for PBKDF key derivation.
func WithParamsKeyLength(keyLen int) ParamsOption {
	return func(p *params) {
		p.keyLen = &keyLen
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
	iter     *int
	keyLen   *int
	hash     func() hash.Hash
}

func newParams(opts ...ParamsOption) *params {
	p := &params{
		password: nil,        // Default password (should be set by caller)
		salt:     nil,        // Default salt (should be set by caller)
		iter:     nil,        // Default iteration count
		keyLen:   nil,        // Default key length (e.g., 256 bits)
		hash:     sha256.New, // Default hash function
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// NewParams creates a new Params instance with the provided options.
func NewParams(opts ...ParamsOption) Params {
	return newParams(opts...)
}

// NewParamsFromDecoder creates a new Params instance by decoding the provided TLV decoder.
func NewParamsFromDecoder(dec tlv.Decoder) (Params, error) {
	p := newParams()
	if err := p.Decode(dec); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *params) Password() ([]byte, bool) {
	if p.password == nil {
		return nil, false
	}
	return p.password, true
}

func (p *params) Salt() ([]byte, bool) {
	if p.salt == nil {
		return nil, false
	}
	return p.salt, true
}

func (p *params) Iterations() (int, bool) {
	if p.iter == nil {
		return 0, false
	}
	return *p.iter, true
}

func (p *params) KeyLength() (int, bool) {
	if p.keyLen == nil {
		return 0, false
	}
	return *p.keyLen, true
}

func (p *params) Hash() hash.Hash {
	return p.hash()
}

func (p *params) Decode(dec tlv.Decoder) error {
	// 3.9. Password-Based Key Derivation Function (PBKDF)
	// 	Crypto_PBKDFParameterSet => STRUCTURE [ tag-order ]
	// {
	//   iterations [1] : UNSIGNED INTEGER [ range 32-bits ],
	//   salt [2] : OCTET STRING [ length 16..32 ],
	// }

	for range 2 {
		if !dec.Next() {
			return dec.Error()
		}
		elem := dec.Element()
		switch t := elem.Tag().(type) {
		case tlv.ContextTag:
			switch t.ContextNumber() {
			case 1:
				v, ok := elem.Unsigned2()
				if !ok {
					return expectedTypeError(tlv.UnsignedInt2, elem)
				}
				iter := int(v)
				p.iter = &iter
			case 2:
				b, ok := elem.Bytes()
				if !ok {
					return expectedTypeError(tlv.OctetString1, elem)
				}
				p.salt = b
			}
		default:
			return expectedTagError(tlv.TagContext, elem.Tag())
		}
	}

	return nil
}

func (p *params) Encode(enc tlv.Encoder, tagNum uint8) error {
	enc.BeginStructure(tlv.NewContextTag(tagNum))
	if p.iter != nil {
		enc.PutUnsigned2(tlv.NewContextTag(pbkdfTagIterations), uint16(*p.iter))
	}
	if p.salt != nil {
		enc.PutOctet(tlv.NewContextTag(pbkdfTagSalt), p.salt)
	}
	return enc.EndContainer()
}

func (p *params) Map() map[string]any {
	m := make(map[string]any)
	if p.password != nil {
		m["password"] = p.password
	}
	if p.iter != nil {
		m["iterations"] = *p.iter
	}
	if p.salt != nil {
		m["salt"] = p.salt
	}
	if p.keyLen != nil {
		m["keyLength"] = *p.keyLen
	}
	return m
}

func (p *params) String() string {
	return json.MustMarshal(p.Map())
}
