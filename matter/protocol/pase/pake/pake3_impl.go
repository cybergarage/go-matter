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

// PakeOptions defines a functional option for configuring the Pake3 message.
type Pake3Option func(*pake3)

// WithPake3CA sets the cA value in the Pake3 message.
func WithPake3CA(cA []byte) Pake3Option {
	return func(p *pake3) {
		p.ca = cA
	}
}

type pake3 struct {
	ca []byte
}

func newPake3(opts ...Pake3Option) *pake3 {
	p := &pake3{
		ca: nil,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

func NewPake3(opts ...Pake3Option) Pake3 {
	return newPake3(opts...)
}

func NewPake3FromBytes(data []byte) (Pake3, error) {
	r := newPake3()
	if err := r.ParseBytes(data); err != nil {
		return nil, err
	}
	return r, nil
}

// ParseBytes parses the given byte slice into the PBKDFPake3 structure.
func (r *pake3) ParseBytes(data []byte) error {
	return r.Decode(tlv.NewDecoderWithBytes(data))
}

// Decode decodes the given TLV decoder into the Pake3 structure.
func (r *pake3) Decode(dec tlv.Decoder) error {
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

	for range 2 {
		if !dec.Next() {
			return dec.Error()
		}
		elem = dec.Element()
		if elem.Type().IsEndOfContainer() {
			break
		}
		switch t := elem.Tag().(type) {
		case tlv.ContextTag:
			switch t.ContextNumber() {
			case 1:
				b, ok := elem.Bytes()
				if !ok {
					return tlv.NewErrExpectedType(tlv.OctetString1, elem)
				}
				r.ca = b
			default:
				return tlv.NewErrExpectedTag(tlv.TagContext, elem.Tag())
			}
		}
	}

	return nil
}

func (p *pake3) cA() []byte {
	return p.ca
}

func (p *pake3) Map() map[string]any {
	return map[string]any{
		"cA": p.ca,
	}
}

func (p *pake3) String() string {
	return json.MustMarshal(p.Map())
}
