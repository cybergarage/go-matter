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

// A.7. Control Octet Encoding
//
//	Bits 7..5 : TagControl (3 bits)
//	Bits 4..0 : ElementType (5 bits)
//
// A.7.1. Element Type Field
// ElementType (5 bits). Each size variant is a distinct constant.
// Only a subset of Matter element types/variants is modeled here for illustration.
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
	// UTF-8 string (length-of-length = 1/2/4/8 bytes).
	ETUtf8String1 ElementType = 0x0A
	ETUtf8String2 ElementType = 0x0B
	ETUtf8String4 ElementType = 0x0C
	ETUtf8String8 ElementType = 0x0D
	// Byte string (length-of-length = 1/2/4/8 bytes).
	ETByteString1 ElementType = 0x0E
	ETByteString2 ElementType = 0x0F
	ETByteString4 ElementType = 0x10
	ETByteString8 ElementType = 0x11
	// Null (no payload).
	ETNull ElementType = 0x12
	// Containers & end marker.
	ETStructure      ElementType = 0x13
	ETArray          ElementType = 0x14
	ETList           ElementType = 0x15
	ETEndOfContainer ElementType = 0x16
	// Floating point.
	ETFloat32 ElementType = 0x17
	ETFloat64 ElementType = 0x18
	// 0x19..0x1F reserved.
)

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
	case ETUtf8String1:
		return 1, true, true
	case ETUtf8String2:
		return 2, true, true
	case ETUtf8String4:
		return 4, true, true
	case ETUtf8String8:
		return 8, true, true
	case ETByteString1:
		return 1, false, true
	case ETByteString2:
		return 2, false, true
	case ETByteString4:
		return 4, false, true
	case ETByteString8:
		return 8, false, true
	default:
		return 0, false, false
	}
}
