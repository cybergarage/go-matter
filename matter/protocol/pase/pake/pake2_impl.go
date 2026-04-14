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

package pake

import (
	"github.com/cybergarage/go-matter/matter/encoding/json"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
)

// Pake2Option defines a functional option for configuring the Pake2 message.
type Pake2Option func(*pake2)

// WithPake2PB sets the responder random value (pB) in the Pake2 message.
func WithPake2PB(pB []byte) Pake2Option {
	return func(p *pake2) {
		p.pb = pB
	}
}

// WithPake2CB sets the cB value in the Pake2 message.
func WithPake2CB(cB []byte) Pake2Option {
	return func(p *pake2) {
		p.cb = cB
	}
}

type pake2 struct {
	pb []byte
	cb []byte
}

func newPake2(opts ...Pake2Option) *pake2 {
	p := &pake2{
		pb: nil,
		cb: nil,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

func NewPake2(opts ...Pake2Option) Pake2 {
	return newPake2(opts...)
}

func NewPake2FromBytes(data []byte) (Pake2, error) {
	p := newPake2()
	if err := p.ParseBytes(data); err != nil {
		return nil, err
	}
	return p, nil
}

// ParseBytes parses the given byte slice into the PBKDFPake2 structure.
func (p *pake2) ParseBytes(data []byte) error {
	return p.Decode(tlv.NewDecoderWithBytes(data))
}

// Decode decodes the given TLV decoder into the Pake2 structure.
func (p *pake2) Decode(dec tlv.Decoder) error {
	// 4.14.1.2. Protocol Details
	// pake-2-struct => STRUCTURE [ tag-order ]
	// {
	//   pB [1] : OCTET STRING [ length CRYPTO_PUBLIC_KEY_SIZE_BYTES ],
	// 	 cB [2] : OCTET STRING [ length CRYPTO_HASH_LEN_BYTES],
	// }

	if !dec.Next() {
		return dec.Error()
	}

	elem := dec.Element()
	if !elem.Type().IsStructure() {
		return tlv.NewErrExpectedType(tlv.Structure, elem)
	}

	for range 3 {
		if !dec.Next() {
			return dec.Error()
		}
		if elem.Type().IsEndOfContainer() {
			break
		}
		elem = dec.Element()
		switch t := elem.Tag().(type) {
		case tlv.ContextTag:
			switch t.ContextNumber() {
			case 1:
				b, ok := elem.Bytes()
				if !ok {
					return tlv.NewErrExpectedType(tlv.OctetString1, elem)
				}
				p.pb = b
			case 2:
				b, ok := elem.Bytes()
				if !ok {
					return tlv.NewErrExpectedType(tlv.OctetString1, elem)
				}
				p.cb = b
			default:
				return tlv.NewErrExpectedTag(tlv.TagContext, elem.Tag())
			}
		}
	}

	return nil
}

func (p *pake2) PB() []byte {
	return p.pb
}

func (p *pake2) CB() []byte {
	return p.cb
}

func (p *pake2) Bytes() ([]byte, error) {
	// 4.14.1.2. Protocol Details
	// pake-2-struct => STRUCTURE [ tag-order ]
	// {
	//   pB [1] : OCTET STRING [ length CRYPTO_PUBLIC_KEY_SIZE_BYTES ],
	// 	 cB [2] : OCTET STRING [ length CRYPTO_HASH_LEN_BYTES],
	// }
	if p.pb == nil {
		return nil, tlv.NewErrMissingField("pB")
	}
	if p.cb == nil {
		return nil, tlv.NewErrMissingField("cB")
	}
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	if err := enc.PutOctet1(tlv.NewContextTag(1), p.pb); err != nil {
		return nil, err
	}
	if err := enc.PutOctet1(tlv.NewContextTag(2), p.cb); err != nil {
		return nil, err
	}
	enc.EndContainer()
	return enc.Bytes(), nil
}

func (p *pake2) Map() map[string]any {
	return map[string]any{
		"pB": p.pb,
		"cB": p.cb,
	}
}

func (p *pake2) String() string {
	return json.MustMarshal(p.Map())
}
