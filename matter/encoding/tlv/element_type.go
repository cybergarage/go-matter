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

// ElementType (5 bits). Each size variant is a distinct constant.
// A.7. Control Octet Encoding
//
//	Bits 7..5 : TagControl (3 bits)
//	Bits 4..0 : ElementType (5 bits)
//
// A.7.1. Element Type Field.
type ElementType uint8

const (
	// Signed integers (little-endian).

	ETSignedInt1 ElementType = 0x00
	ETSignedInt2 ElementType = 0x01
	ETSignedInt4 ElementType = 0x02
	ETSignedInt8 ElementType = 0x03

	// Unsigned integers (little-endian).

	ETUnsignedInt1 ElementType = 0x04
	ETUnsignedInt2 ElementType = 0x05
	ETUnsignedInt4 ElementType = 0x06
	ETUnsignedInt8 ElementType = 0x07

	// Boolean values (no payload).

	ETBoolFalse ElementType = 0x08
	ETBoolTrue  ElementType = 0x09

	// Floating point.

	ETFloat32 ElementType = 0x0A
	ETFloat64 ElementType = 0x0B

	// UTF-8 string (length-of-length = 1/2/4/8 bytes).

	ETUTF8String1 ElementType = 0x0C
	ETUTF8String2 ElementType = 0x0D
	ETUTF8String4 ElementType = 0x0E
	ETUTF8String8 ElementType = 0x0F

	// Octet string (length-of-length = 1/2/4/8 bytes).

	ETOctetString1 ElementType = 0x10
	ETOctetString2 ElementType = 0x11
	ETOctetString4 ElementType = 0x12
	ETOctetString8 ElementType = 0x13

	// Null (no payload).

	ETNull ElementType = 0x14

	// Containers & end marker.

	ETStructure      ElementType = 0x15
	ETArray          ElementType = 0x16
	ETList           ElementType = 0x17
	ETEndOfContainer ElementType = 0x18

	// 0x19..0x1F reserved.
)

// String returns a human-readable name for the ElementType.
func (et ElementType) String() string {
	switch et {
	case ETSignedInt1:
		return "SignedInt1"
	case ETSignedInt2:
		return "SignedInt2"
	case ETSignedInt4:
		return "SignedInt4"
	case ETSignedInt8:
		return "SignedInt8"
	case ETUnsignedInt1:
		return "UnsignedInt1"
	case ETUnsignedInt2:
		return "UnsignedInt2"
	case ETUnsignedInt4:
		return "UnsignedInt4"
	case ETUnsignedInt8:
		return "UnsignedInt8"
	case ETBoolFalse:
		return "BoolFalse"
	case ETBoolTrue:
		return "BoolTrue"
	case ETFloat32:
		return "Float32"
	case ETFloat64:
		return "Float64"
	case ETUTF8String1:
		return "UTF8String1"
	case ETUTF8String2:
		return "UTF8String2"
	case ETUTF8String4:
		return "UTF8String4"
	case ETUTF8String8:
		return "UTF8String8"
	case ETOctetString1:
		return "OctetString1"
	case ETOctetString2:
		return "OctetString2"
	case ETOctetString4:
		return "OctetString4"
	case ETOctetString8:
		return "OctetString8"
	case ETNull:
		return "Null"
	case ETStructure:
		return "Structure"
	case ETArray:
		return "Array"
	case ETList:
		return "List"
	case ETEndOfContainer:
		return "EndOfContainer"
	default:
		return fmt.Sprintf("Unknown(0x%02X)", uint8(et))
	}
}

// containerElement reports whether the element type is a container marker.
func containerElement(et ElementType) bool {
	return et == ETStructure || et == ETArray || et == ETList || et == ETEndOfContainer
}

// numericSigned returns the byte width (1/2/4/8) if et is a signed integer variant.
func numericSigned(et ElementType) int {
	switch et {
	case ETSignedInt1:
		return 1
	case ETSignedInt2:
		return 2
	case ETSignedInt4:
		return 4
	case ETSignedInt8:
		return 8
	default:
		return 0
	}
}

// numericUnsigned returns the byte width (1/2/4/8) if et is an unsigned integer variant.
func numericUnsigned(et ElementType) int {
	switch et {
	case ETUnsignedInt1:
		return 1
	case ETUnsignedInt2:
		return 2
	case ETUnsignedInt4:
		return 4
	case ETUnsignedInt8:
		return 8
	default:
		return 0
	}
}

// floatSize returns 4 or 8 if et is a floating-point variant, else 0.
func floatSize(et ElementType) int {
	switch et {
	case ETFloat32:
		return 4
	case ETFloat64:
		return 8
	default:
		return 0
	}
}

// stringLenFieldSize returns (lengthOfLengthBytes, isUTF8, ok) for string/bytes types.
func stringLenFieldSize(et ElementType) (int, bool, bool) {
	switch et {
	case ETUTF8String1:
		return 1, true, true
	case ETUTF8String2:
		return 2, true, true
	case ETUTF8String4:
		return 4, true, true
	case ETUTF8String8:
		return 8, true, true
	case ETOctetString1:
		return 1, false, true
	case ETOctetString2:
		return 2, false, true
	case ETOctetString4:
		return 4, false, true
	case ETOctetString8:
		return 8, false, true
	default:
		return 0, false, false
	}
}
