// Copyright (C) 2024 The go-matter Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tlv

import (
	"encoding/binary"
)

// Tag represents a TLV tag. It encapsulates the tag control and associated payload bytes, and provides methods for encoding and decoding tags in various forms.
type Tag interface {
	// Control returns the 3-bit TagControl value associated with this tag.
	Control() TagControl
	// Bytes returns the tag payload bytes (may be empty for anonymous).
	Bytes() []byte
	// String returns a human-readable representation of the tag.
	String() string
}

// decodeTagBytes parses raw tag bytes according to the TagControl form.
func decodeTagBytes(tc TagControl, data []byte) (Tag, int, error) {
	switch tc {
	case TagAnonymous:
		return tagAnon{}, 0, nil
	case TagContext:
		if len(data) < 1 {
			return nil, 0, ErrDecodeTagLength
		}
		return tagContext{number: data[0]}, 1, nil
	case TagCommon2:
		if len(data) < 2 {
			return nil, 0, ErrDecodeTagLength
		}
		val := binary.LittleEndian.Uint16(data[0:2])
		return tagCommon2{number: val}, 2, nil
	case TagCommon4:
		if len(data) < 4 {
			return nil, 0, ErrDecodeTagLength
		}
		val := binary.LittleEndian.Uint32(data[0:4])
		return tagCommon4{number: val}, 4, nil
	case TagImplicit2:
		if len(data) < 2 {
			return nil, 0, ErrDecodeTagLength
		}
		val := binary.LittleEndian.Uint16(data[0:2])
		return tagImplicit2{id: val}, 2, nil
	case TagImplicit4:
		if len(data) < 4 {
			return nil, 0, ErrDecodeTagLength
		}
		val := binary.LittleEndian.Uint32(data[0:4])
		return tagImplicit4{id: val}, 4, nil
	case TagFullyQualified6:
		if len(data) < 6 {
			return nil, 0, ErrDecodeTagLength
		}
		v := binary.LittleEndian.Uint16(data[0:2])
		p := binary.LittleEndian.Uint16(data[2:4])
		t := binary.LittleEndian.Uint16(data[4:6])
		return tagFQ6{vendor: v, profile: p, num: t}, 6, nil
	case TagFullyQualified8:
		if len(data) < 8 {
			return nil, 0, ErrDecodeTagLength
		}
		v := binary.LittleEndian.Uint16(data[0:2])
		p := binary.LittleEndian.Uint16(data[2:4])
		t := binary.LittleEndian.Uint32(data[4:8])
		return tagFQ8{vendor: v, profile: p, num: t}, 8, nil
	default:
		return nil, 0, ErrTagUnsupportedForm
	}
}
