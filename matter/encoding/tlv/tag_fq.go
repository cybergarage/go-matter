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

// FullyQualified6 represents a 6-byte fully-qualified tag.
type FullyQualified6 interface {
	Tag
	// VendorID returns the 2-byte vendor ID.
	VendorID() uint16
	// ProfileNumber returns the 2-byte profile number.
	ProfileNumber() uint16
	// TagNumber returns the 2-byte tag number.
	TagNumber() uint16
}

// tagFQ6 is a 6-byte fully-qualified tag (Vendor(2)+Profile(2)+Tag(2)).
type tagFQ6 struct {
	vendor  uint16
	profile uint16
	num     uint16
}

// NewFullyQualified6 constructs a 6-byte fully-qualified tag.
func NewFullyQualified6(vendor, profile, num uint16) FullyQualified6 {
	return tagFQ6{vendor: vendor, profile: profile, num: num}
}

// Control returns TagCtlFullyQualified6.
func (t tagFQ6) Control() TagControl { return TagFullyQualified6 }

// VendorID returns the 2-byte vendor ID.
func (t tagFQ6) VendorID() uint16 { return t.vendor }

// ProfileNumber returns the 2-byte profile number.
func (t tagFQ6) ProfileNumber() uint16 { return t.profile }

// TagNumber returns the 2-byte tag number.
func (t tagFQ6) TagNumber() uint16 { return t.num }

// Bytes returns the 6-byte payload.
func (t tagFQ6) Bytes() []byte {
	b := make([]byte, 6)
	binary.LittleEndian.PutUint16(b[0:2], t.vendor)
	binary.LittleEndian.PutUint16(b[2:4], t.profile)
	binary.LittleEndian.PutUint16(b[4:6], t.num)
	return b
}

// String returns a descriptive representation of the 6-byte fully-qualified tag.
func (t tagFQ6) String() string {
	return fmt.Sprintf("FQ6(V=0x%04X,P=0x%04X,T=0x%04X)", t.vendor, t.profile, t.num)
}

// FullyQualified8 represents an 8-byte fully-qualified tag.
type FullyQualified8 interface {
	Tag
	// VendorID returns the 2-byte vendor ID.
	VendorID() uint16
	// ProfileNumber returns the 2-byte profile number.
	ProfileNumber() uint16
	// TagNumber returns the 4-byte tag number.
	TagNumber() uint32
}

// tagFQ8 is an 8-byte fully-qualified tag (Vendor(2)+Profile(2)+Tag(4)).
type tagFQ8 struct {
	vendor  uint16
	profile uint16
	num     uint32
}

// NewFullyQualified8 constructs an 8-byte fully-qualified tag.
func NewFullyQualified8(vendor, profile uint16, num uint32) FullyQualified8 {
	return tagFQ8{vendor: vendor, profile: profile, num: num}
}

// Control returns TagCtlFullyQualified8.
func (t tagFQ8) Control() TagControl { return TagFullyQualified8 }

// VendorID returns the 2-byte vendor ID.
func (t tagFQ8) VendorID() uint16 { return t.vendor }

// ProfileNumber returns the 2-byte profile number.
func (t tagFQ8) ProfileNumber() uint16 { return t.profile }

// TagNumber returns the 4-byte tag number.
func (t tagFQ8) TagNumber() uint32 { return t.num }

// Bytes returns the 8-byte payload.
func (t tagFQ8) Bytes() []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint16(b[0:2], t.vendor)
	binary.LittleEndian.PutUint16(b[2:4], t.profile)
	binary.LittleEndian.PutUint32(b[4:8], t.num)
	return b
}

// String returns a descriptive representation of the 8-byte fully-qualified tag.
func (t tagFQ8) String() string {
	return fmt.Sprintf("FQ8(V=0x%04X,P=0x%04X,T=0x%08X)", t.vendor, t.profile, t.num)
}
