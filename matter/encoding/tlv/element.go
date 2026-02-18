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
	"encoding/binary"
	"fmt"
	"math"
)

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

// elementImpl is the concrete (private) implementation of Element.
type elementImpl struct {
	tag Tag
	et  ElementType

	signedValue   *int64
	unsignedValue *uint64
	boolValue     *bool
	floatValue    *float64
	strValue      *string
	bytesValue    *[]byte
}

var _ Element = (*elementImpl)(nil)

func (e *elementImpl) Tag() Tag { return e.tag }

func (e *elementImpl) Type() ElementType { return e.et }

func (e *elementImpl) Signed() (int64, bool) {
	if e.signedValue != nil {
		return *e.signedValue, true
	}
	return 0, false
}

func (e *elementImpl) Signed1() (int8, bool) {
	v, ok := e.Signed()
	if !ok {
		return 0, false
	}
	if v < math.MinInt8 || v > math.MaxInt8 {
		return 0, false
	}
	return int8(v), true
}

func (e *elementImpl) Signed2() (int16, bool) {
	v, ok := e.Signed()
	if !ok {
		return 0, false
	}
	if v < math.MinInt16 || v > math.MaxInt16 {
		return 0, false
	}
	return int16(v), true
}

func (e *elementImpl) Signed4() (int32, bool) {
	v, ok := e.Signed()
	if !ok {
		return 0, false
	}
	if v < math.MinInt32 || v > math.MaxInt32 {
		return 0, false
	}
	return int32(v), true
}

func (e *elementImpl) Signed8() (int64, bool) {
	return e.Signed()
}

func (e *elementImpl) Unsigned() (uint64, bool) {
	if e.unsignedValue != nil {
		return *e.unsignedValue, true
	}
	return 0, false
}

func (e *elementImpl) Unsigned1() (uint8, bool) {
	v, ok := e.Unsigned()
	if !ok {
		return 0, false
	}
	if v > math.MaxUint8 {
		return 0, false
	}
	return uint8(v), true
}

func (e *elementImpl) Unsigned2() (uint16, bool) {
	v, ok := e.Unsigned()
	if !ok {
		return 0, false
	}
	if v > math.MaxUint16 {
		return 0, false
	}
	return uint16(v), true
}

func (e *elementImpl) Unsigned4() (uint32, bool) {
	v, ok := e.Unsigned()
	if !ok {
		return 0, false
	}
	if v > math.MaxUint32 {
		return 0, false
	}
	return uint32(v), true
}

func (e *elementImpl) Unsigned8() (uint64, bool) {
	return e.Unsigned()
}

func (e *elementImpl) Bool() (bool, bool) {
	if e.boolValue != nil {
		return *e.boolValue, true
	}
	return false, false
}

func (e *elementImpl) Float() (float64, bool) {
	if e.floatValue != nil {
		return *e.floatValue, true
	}
	return 0, false
}

func (e *elementImpl) UTF8() (string, bool) {
	if e.strValue != nil {
		return *e.strValue, true
	}
	return "", false
}

func (e *elementImpl) Bytes() ([]byte, bool) {
	if e.bytesValue != nil {
		return *e.bytesValue, true
	}
	return nil, false
}

func (e *elementImpl) String() string {
	switch e.et {
	case SignedInt1, SignedInt2, SignedInt4, SignedInt8:
		if v, ok := e.Signed(); ok {
			return fmt.Sprintf("%s Signed=%d", e.tag, v)
		}
	case UnsignedInt1, UnsignedInt2, UnsignedInt4, UnsignedInt8:
		if v, ok := e.Unsigned(); ok {
			return fmt.Sprintf("%s Unsigned=%d", e.tag, v)
		}
	case BoolFalse, BoolTrue:
		if v, ok := e.Bool(); ok {
			return fmt.Sprintf("%s Bool=%v", e.tag, v)
		}
	case Float32, Float64:
		if v, ok := e.Float(); ok {
			return fmt.Sprintf("%s Float=%v", e.tag, v)
		}
	case UTF8String1, UTF8String2, UTF8String4, UTF8String8:
		if s, ok := e.UTF8(); ok {
			return fmt.Sprintf("%s UTF8=%q", e.tag, s)
		}
	case OctetString1, OctetString2, OctetString4, OctetString8:
		if b, ok := e.Bytes(); ok {
			return fmt.Sprintf("%s Bytes(%d)", e.tag, len(b))
		}
	case Null:
		return fmt.Sprintf("%s Null", e.tag)
	case Structure:
		return fmt.Sprintf("%s <Structure>", e.tag)
	case Array:
		return fmt.Sprintf("%s <Array>", e.tag)
	case List:
		return fmt.Sprintf("%s <List>", e.tag)
	case EndOfContainer:
		return "EndOfContainer"
	}
	return fmt.Sprintf("%s Type=0x%02X", e.tag, uint8(e.et))
}

// Primitive decoding helpers.

func decodeSigned(le []byte) int64 {
	switch len(le) {
	case 1:
		return int64(int8(le[0]))
	case 2:
		return int64(int16(binary.LittleEndian.Uint16(le)))
	case 4:
		return int64(int32(binary.LittleEndian.Uint32(le)))
	case 8:
		return int64(binary.LittleEndian.Uint64(le))
	default:
		return 0
	}
}

func decodeUnsigned(le []byte) uint64 {
	switch len(le) {
	case 1:
		return uint64(le[0])
	case 2:
		return uint64(binary.LittleEndian.Uint16(le))
	case 4:
		return uint64(binary.LittleEndian.Uint32(le))
	case 8:
		return binary.LittleEndian.Uint64(le)
	default:
		return 0
	}
}

func decodeFloat(le []byte) float64 {
	switch len(le) {
	case 4:
		u := binary.LittleEndian.Uint32(le)
		return float64(math.Float32frombits(u))
	case 8:
		u := binary.LittleEndian.Uint64(le)
		return math.Float64frombits(u)
	default:
		return 0
	}
}
