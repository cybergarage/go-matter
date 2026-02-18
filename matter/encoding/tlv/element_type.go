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

import (
	"fmt"
)

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

// IsSignedInt returns true if the ElementType is any signed integer variant.
func (et ElementType) IsSignedInt() bool {
	return et == SignedInt1 || et == SignedInt2 || et == SignedInt4 || et == SignedInt8
}

// IsSignedInt1 returns true if the ElementType is SignedInt1.
func (et ElementType) IsSignedInt1() bool {
	return et == SignedInt1
}

// IsSignedInt2 returns true if the ElementType is SignedInt2.
func (et ElementType) IsSignedInt2() bool {
	return et == SignedInt2
}

// IsSignedInt4 returns true if the ElementType is SignedInt4.
func (et ElementType) IsSignedInt4() bool {
	return et == SignedInt4
}

// IsSignedInt8 returns true if the ElementType is SignedInt8.
func (et ElementType) IsSignedInt8() bool {
	return et == SignedInt8
}

// IsUnsignedInt returns true if the ElementType is any unsigned integer variant.
func (et ElementType) IsUnsignedInt() bool {
	return et == UnsignedInt1 || et == UnsignedInt2 || et == UnsignedInt4 || et == UnsignedInt8
}

// IsUnsignedInt1 returns true if the ElementType is UnsignedInt1.
func (et ElementType) IsUnsignedInt1() bool {
	return et == UnsignedInt1
}

// IsUnsignedInt2 returns true if the ElementType is UnsignedInt2.
func (et ElementType) IsUnsignedInt2() bool {
	return et == UnsignedInt2
}

// IsUnsignedInt4 returns true if the ElementType is UnsignedInt4.
func (et ElementType) IsUnsignedInt4() bool {
	return et == UnsignedInt4
}

// IsUnsignedInt8 returns true if the ElementType is UnsignedInt8.
func (et ElementType) IsUnsignedInt8() bool {
	return et == UnsignedInt8
}

// IsBool returns true if the ElementType is any boolean variant.
func (et ElementType) IsBool() bool {
	return et == BoolFalse || et == BoolTrue
}

// IsTrue returns true if the ElementType is BoolTrue.
func (et ElementType) IsTrue() bool {
	return et == BoolTrue
}

// IsFalse returns true if the ElementType is BoolFalse.
func (et ElementType) IsFalse() bool {
	return et == BoolFalse
}

// IsFloat returns true if the ElementType is any floating-point variant.
func (et ElementType) IsFloat() bool {
	return et == Float32 || et == Float64
}

// IsFloat32 returns true if the ElementType is Float32.
func (et ElementType) IsFloat32() bool {
	return et == Float32
}

// IsFloat64 returns true if the ElementType is Float64.
func (et ElementType) IsFloat64() bool {
	return et == Float64
}

// IsUTF8String returns true if the ElementType is any UTF-8 string variant.
func (et ElementType) IsUTF8String() bool {
	return et == UTF8String1 || et == UTF8String2 || et == UTF8String4 || et == UTF8String8
}

// IsUTF8String1 returns true if the ElementType is UTF8String1.
func (et ElementType) IsUTF8String1() bool {
	return et == UTF8String1
}

// IsUTF8String2 returns true if the ElementType is UTF8String2.
func (et ElementType) IsUTF8String2() bool {
	return et == UTF8String2
}

// IsUTF8String4 returns true if the ElementType is UTF8String4.
func (et ElementType) IsUTF8String4() bool {
	return et == UTF8String4
}

// IsUTF8String8 returns true if the ElementType is UTF8String8.
func (et ElementType) IsUTF8String8() bool {
	return et == UTF8String8
}

// IsOctetString returns true if the ElementType is any octet string variant.
func (et ElementType) IsOctetString() bool {
	return et == OctetString1 || et == OctetString2 || et == OctetString4 || et == OctetString8
}

// IsOctetString1 returns true if the ElementType is OctetString1.
func (et ElementType) IsOctetString1() bool {
	return et == OctetString1
}

// IsOctetString2 returns true if the ElementType is OctetString2.
func (et ElementType) IsOctetString2() bool {
	return et == OctetString2
}

// IsOctetString4 returns true if the ElementType is OctetString4.
func (et ElementType) IsOctetString4() bool {
	return et == OctetString4
}

// IsOctetString8 returns true if the ElementType is OctetString8.
func (et ElementType) IsOctetString8() bool {
	return et == OctetString8
}

// IsNull returns true if the ElementType is Null.
func (et ElementType) IsNull() bool {
	return et == Null
}

// IsContainer returns true if the ElementType is a container marker (Structure, Array, List, or EndOfContainer).
func (et ElementType) IsContainer() bool {
	return containerElement(et)
}

// IsStructure returns true if the ElementType is Structure.
func (et ElementType) IsStructure() bool {
	return et == Structure
}

// IsArray returns true if the ElementType is Array.
func (et ElementType) IsArray() bool {
	return et == Array
}

// IsList returns true if the ElementType is List.
func (et ElementType) IsList() bool {
	return et == List
}

// IsEndOfContainer returns true if the ElementType is the EndOfContainer marker.
func (et ElementType) IsEndOfContainer() bool {
	return et == EndOfContainer
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
