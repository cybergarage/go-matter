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

// Common2Tag represents a 2-byte common/profile tag.
type Common2Tag interface {
	Tag
	// CommonNumber returns the 2-byte tag value (e.g. profile ID).
	CommonNumber() uint16
}

// tagCommon2 is a common/profile form with 2 bytes.
type tagCommon2 struct {
	number uint16
}

// NewCommon2Tag constructs a 2-byte common/profile tag.
func NewCommon2Tag(profile uint16) Common2Tag { return tagCommon2{number: profile} }

// Control returns TagCtlCommon2.
func (t tagCommon2) Control() TagControl { return TagCommon2 }

func (t tagCommon2) CommonNumber() uint16 { return t.number }

// Bytes returns 2 bytes (little-endian).
func (t tagCommon2) Bytes() []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, t.number)
	return b
}

// String returns a descriptive representation.
func (t tagCommon2) String() string { return fmt.Sprintf("Common2(0x%04X)", t.number) }

// Common4Tag represents a 4-byte common/extended profile tag.
type Common4Tag interface {
	Tag
	// CommonNumber returns the 4-byte tag value (e.g. profile ID or fully qualified tag).
	CommonNumber() uint32
}

// tagCommon4 is a 4-byte common/extended profile tag.
type tagCommon4 struct {
	number uint32
}

// NewCommon4Tag constructs a 4-byte common/extended tag.
func NewCommon4Tag(val uint32) Common4Tag { return tagCommon4{number: val} }

// Control returns TagCtlCommon4.
func (t tagCommon4) Control() TagControl { return TagCommon4 }

func (t tagCommon4) CommonNumber() uint32 { return t.number }

// Bytes returns the 4-byte little-endian payload.
func (t tagCommon4) Bytes() []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, t.number)
	return b
}

// String returns a descriptive representation of the 4-byte common tag.
func (t tagCommon4) String() string { return fmt.Sprintf("Common4(0x%08X)", t.number) }
