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
	"fmt"
)

// Implicit2 represents a 2-byte implicit profile tag.
type Implicit2 interface {
	Tag
	// ImplicitNumber returns the 2-byte profile ID encoded in the payload.
	ImplicitNumber() uint16
}

type tagImplicit2 struct {
	id uint16
}

// NewImplicit2Tag constructs a 2-byte implicit profile tag.
func NewImplicit2Tag(profile uint16) Implicit2 { return tagImplicit2{id: profile} }

// Control returns TagCtlImplicit2.
func (t tagImplicit2) Control() TagControl { return TagImplicit2 }

// ImplicitNumber returns the 2-byte profile ID encoded in the payload.
func (t tagImplicit2) ImplicitNumber() uint16 { return t.id }

// Bytes returns 2 bytes (little-endian).
func (t tagImplicit2) Bytes() []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, t.id)
	return b
}

// String returns a descriptive representation.
func (t tagImplicit2) String() string { return fmt.Sprintf("Implicit2(0x%04X)", t.id) }

// Implicit4 represents a 4-byte implicit profile tag.
type Implicit4 interface {
	Tag
	// ImplicitNumber returns the 4-byte profile ID encoded in the payload.
	ImplicitNumber() uint32
}
type tagImplicit4 struct {
	id uint32
}

// NewImplicit4Tag constructs a 4-byte implicit profile tag.
func NewImplicit4Tag(profile uint32) Implicit4 { return tagImplicit4{id: profile} }

// Control returns TagCtlImplicit4.
func (t tagImplicit4) Control() TagControl { return TagImplicit4 }

// ImplicitNumber returns the 4-byte profile ID encoded in the payload.
func (t tagImplicit4) ImplicitNumber() uint32 { return t.id }

// Bytes returns 4 bytes (little-endian).
// Bytes returns the 4-byte little-endian payload.
func (t tagImplicit4) Bytes() []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, t.id)
	return b
}

// String returns a descriptive representation of the 4-byte implicit tag.
func (t tagImplicit4) String() string { return fmt.Sprintf("Implicit4(0x%08X)", t.id) }
