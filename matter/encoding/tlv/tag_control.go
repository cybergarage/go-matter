// Copyright (C) 2024 The go-matter Authors. All rights reserved.
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

package tlv

import "fmt"

// TagControl represents the 3-bit tag control field in the control octet.
// Each value determines how many tag bytes follow the control octet.
// Some values are illustrative (e.g. FullyQualified6 vs FullyQualified8) and
// may need adjustment to match a specific spec revision exactly.
//
// A.7. Control Octet Encoding
//
//	Bits 7..5 : TagControl (3 bits)
//	Bits 4..0 : ElementType (5 bits)
//
// A.7.2. Tag Control Field.
type TagControl uint8

const (
	// TagAnonymous indicates there are no tag bytes.
	TagAnonymous TagControl = 0x00
	// TagContext indicates a 1-byte context tag.
	TagContext TagControl = 0x01
	// TagCommon2 indicates a 2-byte common profile tag.
	TagCommon2 TagControl = 0x02
	// TagCommon4 indicates a 4-byte common profile tag.
	TagCommon4 TagControl = 0x03
	// TagImplicit2 indicates a 2-byte implicit profile tag.
	TagImplicit2 TagControl = 0x04
	// TagImplicit4 indicates a 4-byte implicit profile tag.
	TagImplicit4 TagControl = 0x05
	// TagFullyQualified6 indicates a 6-byte fully-qualified tag (2+2+2).
	TagFullyQualified6 TagControl = 0x06
	// TagFullyQualified8 indicates an 8-byte fully-qualified tag (2+2+4).
	TagFullyQualified8 TagControl = 0x07
)

// String returns a human-readable name for the TagControl value.
func (tc TagControl) String() string {
	switch tc {
	case TagAnonymous:
		return "Anonymous"
	case TagContext:
		return "Context"
	case TagCommon2:
		return "Common2"
	case TagCommon4:
		return "Common4"
	case TagImplicit2:
		return "Implicit2"
	case TagImplicit4:
		return "Implicit4"
	case TagFullyQualified6:
		return "FullyQualified6"
	case TagFullyQualified8:
		return "FullyQualified8"
	default:
		return fmt.Sprintf("Unknown(%d)", tc)
	}
}

// encodeControl composes the control octet from tag control and element type.
func encodeControl(tc TagControl, et ElementType) byte {
	return byte((uint8(tc) << 5) | (uint8(et) & 0x1F))
}

// decodeControl splits a control octet into tag control and element type.
func decodeControl(b byte) (TagControl, ElementType) {
	tc := TagControl((b >> 5) & 0x07)
	et := ElementType(b & 0x1F)
	return tc, et
}
