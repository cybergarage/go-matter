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

// Element represents a decoded TLV element.
type Element interface {
	// Tag returns the tag for this element.
	Tag() Tag
	// Type returns the raw ElementType.
	Type() ElementType

	// Signed returns the signed integer value if this is one of the signed int variants.
	Signed() (int64, bool)
	// Signed1  returns the int8 value if this is SignedInt1, along with a boolean indicating success.
	Signed1() (int8, bool)
	// Signed2 returns the int16 value if this is SignedInt2, along with a boolean indicating success.
	Signed2() (int16, bool)
	// Signed4 returns the int32 value if this is SignedInt4, along with a boolean indicating success.
	Signed4() (int32, bool)
	// Signed8 returns the int64 value if this is SignedInt8, along with a boolean indicating success.
	Signed8() (int64, bool)

	// Unsigned returns the unsigned integer value if this is one of the unsigned int variants.
	Unsigned() (uint64, bool)
	// Unsigned1 returns the uint8 value if this is UnsignedInt1, along with a boolean indicating success.
	Unsigned1() (uint8, bool)
	// Unsigned2 returns the uint16 value if this is UnsignedInt2, along with a boolean indicating success.
	Unsigned2() (uint16, bool)
	// Unsigned4 returns the uint32 value if this is UnsignedInt4, along with a boolean indicating success.
	Unsigned4() (uint32, bool)
	// Unsigned8 returns the uint64 value if this is UnsignedInt8, along with a boolean indicating success.
	Unsigned8() (uint64, bool)

	// Bool returns the boolean value if this is BoolTrue or BoolFalse.
	Bool() (bool, bool)

	// Float returns the floating point value (float32 widened to float64) if this is float32/64.
	Float() (float64, bool)

	// UTF8 returns the UTF-8 string if this is one of the UTF-8 string types.
	UTF8() (string, bool)

	// Bytes returns a copy of the underlying byte slice if this is a byte string type.
	Bytes() ([]byte, bool)

	// String returns a human-readable description (for logging/debugging).
	String() string
}
