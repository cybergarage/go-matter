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

	SignedInt1 ElementType = 0x00
	SignedInt2 ElementType = 0x01
	SignedInt4 ElementType = 0x02
	SignedInt8 ElementType = 0x03

	// Unsigned integers (little-endian).

	UnsignedInt1 ElementType = 0x04
	UnsignedInt2 ElementType = 0x05
	UnsignedInt4 ElementType = 0x06
	UnsignedInt8 ElementType = 0x07

	// Boolean values (no payload).

	BoolFalse ElementType = 0x08
	BoolTrue  ElementType = 0x09

	// Floating point.

	Float32 ElementType = 0x0A
	Float64 ElementType = 0x0B

	// UTF-8 string (length-of-length = 1/2/4/8 bytes).

	UTF8String1 ElementType = 0x0C
	UTF8String2 ElementType = 0x0D
	UTF8String4 ElementType = 0x0E
	UTF8String8 ElementType = 0x0F

	// Octet string (length-of-length = 1/2/4/8 bytes).

	OctetString1 ElementType = 0x10
	OctetString2 ElementType = 0x11
	OctetString4 ElementType = 0x12
	OctetString8 ElementType = 0x13

	// Null (no payload).

	Null ElementType = 0x14

	// Containers & end marker.

	Structure      ElementType = 0x15
	Array          ElementType = 0x16
	List           ElementType = 0x17
	EndOfContainer ElementType = 0x18

	// 0x19..0x1F reserved.
)

// Is returns true if the ElementType matches the given type.
func (et ElementType) Is(t ElementType) bool {
	return et == t
}

// String returns a human-readable name for the ElementType.
func (et ElementType) String() string {
	switch et {
	case SignedInt1:
		return "SignedInt1"
	case SignedInt2:
		return "SignedInt2"
	case SignedInt4:
		return "SignedInt4"
	case SignedInt8:
		return "SignedInt8"
	case UnsignedInt1:
		return "UnsignedInt1"
	case UnsignedInt2:
		return "UnsignedInt2"
	case UnsignedInt4:
		return "UnsignedInt4"
	case UnsignedInt8:
		return "UnsignedInt8"
	case BoolFalse:
		return "BoolFalse"
	case BoolTrue:
		return "BoolTrue"
	case Float32:
		return "Float32"
	case Float64:
		return "Float64"
	case UTF8String1:
		return "UTF8String1"
	case UTF8String2:
		return "UTF8String2"
	case UTF8String4:
		return "UTF8String4"
	case UTF8String8:
		return "UTF8String8"
	case OctetString1:
		return "OctetString1"
	case OctetString2:
		return "OctetString2"
	case OctetString4:
		return "OctetString4"
	case OctetString8:
		return "OctetString8"
	case Null:
		return "Null"
	case Structure:
		return "Structure"
	case Array:
		return "Array"
	case List:
		return "List"
	case EndOfContainer:
		return "EndOfContainer"
	default:
		return fmt.Sprintf("Unknown(0x%02X)", uint8(et))
	}
}

// containerElement reports whether the element type is a container marker.
func containerElement(et ElementType) bool {
	return et == Structure || et == Array || et == List || et == EndOfContainer
}

// numericSigned returns the byte width (1/2/4/8) if et is a signed integer variant.
func numericSigned(et ElementType) int {
	switch et {
	case SignedInt1:
		return 1
	case SignedInt2:
		return 2
	case SignedInt4:
		return 4
	case SignedInt8:
		return 8
	default:
		return 0
	}
}

// numericUnsigned returns the byte width (1/2/4/8) if et is an unsigned integer variant.
func numericUnsigned(et ElementType) int {
	switch et {
	case UnsignedInt1:
		return 1
	case UnsignedInt2:
		return 2
	case UnsignedInt4:
		return 4
	case UnsignedInt8:
		return 8
	default:
		return 0
	}
}

// floatSize returns 4 or 8 if et is a floating-point variant, else 0.
func floatSize(et ElementType) int {
	switch et {
	case Float32:
		return 4
	case Float64:
		return 8
	default:
		return 0
	}
}

// stringLenFieldSize returns (lengthOfLengthBytes, isUTF8) for string/bytes types.
func stringLenFieldSize(et ElementType) (int, bool) {
	switch et {
	case UTF8String1:
		return 1, true
	case UTF8String2:
		return 2, true
	case UTF8String4:
		return 4, true
	case UTF8String8:
		return 8, true
	case OctetString1:
		return 1, false
	case OctetString2:
		return 2, false
	case OctetString4:
		return 4, false
	case OctetString8:
		return 8, false
	default:
		return 0, false
	}
}
