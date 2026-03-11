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

// Pake1Option defines a functional option for configuring the Pake1 message.
type Pake1Option func(*pake1)

// WithPake1PA sets the initiator random value (pA) in the Pake1 message.
func WithPake1PA(pA []byte) Pake1Option {
	return func(p *pake1) {
		p.pa = pA
	}
}

type pake1 struct {
	pa []byte
}

func newPake1(opts ...Pake1Option) *pake1 {
	p := &pake1{
		pa: nil,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// NewPake1 creates a new Pake1 message using the provided options.
func NewPake1(opts ...Pake1Option) Pake1 {
	return newPake1(opts...)
}

// NewPake1FromBytes creates a new Pake1 message by parsing the given byte slice.
func NewPake1FromBytes(data []byte) (Pake1, error) {
	p := newPake1()
	if err := p.ParseBytes(data); err != nil {
		return nil, err
	}
	return p, nil
}

// ParseBytes parses the given byte slice into the PBKDFPake1 structure.
func (p *pake1) ParseBytes(data []byte) error {
	return p.Decode(tlv.NewDecoderWithBytes(data))
}

// Decode decodes the given TLV decoder into the Pake1 structure.
func (p *pake1) Decode(dec tlv.Decoder) error {
	// 4.14.1.2. Protocol Details
	// pake-1-struct => STRUCTURE [ tag-order ]
	// {
	//   pA [1] : OCTET STRING [ length CRYPTO_PUBLIC_KEY_SIZE_BYTES ],
	// }

	if !dec.Next() {
		return dec.Error()
	}

	elem := dec.Element()
	if !elem.Type().IsStructure() {
		return tlv.NewErrExpectedType(tlv.Structure, elem)
	}

	for range 2 {
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
				p.pa = b
			default:
				return tlv.NewErrExpectedTag(tlv.TagContext, elem.Tag())
			}
		}
	}

	return nil
}

func (p *pake1) pA() []byte {
	return p.pa
}

func (p *pake1) Bytes() ([]byte, error) {
	// 4.14.1.2. Protocol Details
	// pake-1-struct => STRUCTURE [ tag-order ]
	// {
	//   pA [1] : OCTET STRING [ length CRYPTO_PUBLIC_KEY_SIZE_BYTES ],
	// }
	if p.pa == nil {
		return nil, tlv.NewErrMissingField("pA")
	}
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	if err := enc.PutOctet1(tlv.NewContextTag(1), p.pa); err != nil {
		return nil, err
	}
	if err := enc.EndContainer(); err != nil {
		return nil, err
	}
	return enc.Bytes(), nil
}

func (p *pake1) Map() map[string]any {
	return map[string]any{
		"pA": p.pa,
	}
}

func (p *pake1) String() string {
	return json.MustMarshal(p.Map())
}
