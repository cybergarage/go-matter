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

// Encoder defines the interface for producing TLV-encoded data using the
// control octet format (TagControl in bits 7..5, ElementType in bits 4..0).
type Encoder interface {
	// PutSigned encodes a signed integer using the minimal fitting size (1/2/4/8).
	PutSigned(tag Tag, v int64) error
	// PutSigned1 encodes an int8 value (SignedInt1).
	PutSigned1(tag Tag, v int8) error
	// PutSigned2 encodes an int16 value (SignedInt2).
	PutSigned2(tag Tag, v int16) error
	// PutSigned4 encodes an int32 value (SignedInt4).
	PutSigned4(tag Tag, v int32) error
	// PutSigned8 encodes an int64 value (SignedInt8).
	PutSigned8(tag Tag, v int64) error

	// PutUnsigned encodes an unsigned integer using the minimal fitting size (1/2/4/8).
	PutUnsigned(tag Tag, v uint64) error
	// PutUnsigned1 encodes a uint8 value (UnsignedInt1).
	PutUnsigned1(tag Tag, v uint8) error
	// PutUnsigned2 encodes a uint16 value (UnsignedInt2).
	PutUnsigned2(tag Tag, v uint16) error
	// PutUnsigned4 encodes a uint32 value (UnsignedInt4).
	PutUnsigned4(tag Tag, v uint32) error
	// PutUnsigned8 encodes a uint64 value (UnsignedInt8).
	PutUnsigned8(tag Tag, v uint64) error

	// PutBool encodes a boolean (selects ETBoolFalse or BoolTrue).
	PutBool(tag Tag, v bool)
	// PutNull encodes a null element (no payload).
	PutNull(tag Tag)
	// PutFloat32 encodes a 32-bit floating point value (Float32).
	PutFloat32(tag Tag, f float32)
	// PutFloat64 encodes a 64-bit floating point value (Float64).
	PutFloat64(tag Tag, f float64)
	// PutUTF8 encodes a UTF-8 string with an adaptive length-of-length field.
	PutUTF8(tag Tag, s string) error
	// PutBytes encodes a raw byte slice with an adaptive length-of-length field.
	PutBytes(tag Tag, b []byte) error

	// BeginStructure emits the Structure container start.
	BeginStructure(tag Tag)
	// BeginArray emits the Array container start.
	BeginArray(tag Tag)
	// BeginList emits the List container start.
	BeginList(tag Tag)
	// EndContainer emits an EndOfContainer marker for the most recent container.
	EndContainer() error
	// MustEndAll closes all open containers (ignoring errors).
	MustEndAll()

	// Bytes returns the accumulated encoded bytes. The returned slice must not be mutated.
	Bytes() []byte
}
