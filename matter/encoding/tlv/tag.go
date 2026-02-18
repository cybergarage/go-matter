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

// Tag is the interface every tag variant implements.
// Control returns the TagControl code for the tag.
// SerializeTag returns the raw tag bytes (without the control octet).
// String returns a human-readable representation for debugging/logging.
type Tag interface {
	// Control returns the 3-bit TagControl value associated with this tag.
	Control() TagControl
	// SerializeTag returns the tag payload bytes (may be empty for anonymous).
	SerializeTag() []byte
	// String returns a human-readable representation of the tag.
	String() string
}

// tagAnon is the anonymous tag implementation (no payload bytes).
type tagAnon struct{}

// Control returns TagCtlAnonymous.
func (t tagAnon) Control() TagControl { return TagAnonymous }

// SerializeTag returns nil (anonymous tag has no payload).
func (t tagAnon) SerializeTag() []byte { return nil }

// String returns a descriptive name for the anonymous tag.
func (t tagAnon) String() string { return "(anon)" }

// AnonymousTag constructs a Tag representing an anonymous tag.
func AnonymousTag() Tag { return tagAnon{} }

// tagContext is a context-specific tag with a 1-byte number.
type tagContext struct {
	Num uint8
}

// Control returns TagCtlContext.
func (t tagContext) Control() TagControl { return TagContext }

// SerializeTag returns the single context tag byte.
func (t tagContext) SerializeTag() []byte { return []byte{t.Num} }

// String returns a descriptive string for the context tag.
func (t tagContext) String() string { return fmt.Sprintf("Context(%d)", t.Num) }

// ContextTag constructs a context-specific tag with the given 1-byte number.
func ContextTag(num uint8) Tag { return tagContext{Num: num} }

// tagCommon2 is a common/profile form with 2 bytes.
type tagCommon2 struct {
	Profile uint16
}

// Control returns TagCtlCommon2.
func (t tagCommon2) Control() TagControl { return TagCommon2 }

// SerializeTag returns 2 bytes (little-endian).
func (t tagCommon2) SerializeTag() []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, t.Profile)
	return b
}

// String returns a descriptive representation.
func (t tagCommon2) String() string { return fmt.Sprintf("Common2(0x%04X)", t.Profile) }

// Common2Tag constructs a 2-byte common/profile tag.
func Common2Tag(profile uint16) Tag { return tagCommon2{Profile: profile} }

// tagCommon4 is a 4-byte common/extended profile tag.
type tagCommon4 struct {
	Value uint32
}

// Control returns TagCtlCommon4.
func (t tagCommon4) Control() TagControl { return TagCommon4 }

// SerializeTag returns the 4-byte little-endian payload.
func (t tagCommon4) SerializeTag() []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, t.Value)
	return b
}

// String returns a descriptive representation of the 4-byte common tag.
func (t tagCommon4) String() string { return fmt.Sprintf("Common4(0x%08X)", t.Value) }

// Common4Tag constructs a 4-byte common/extended tag.
func Common4Tag(val uint32) Tag { return tagCommon4{Value: val} }

// tagFQ6 is a 6-byte fully-qualified tag (Vendor(2)+Profile(2)+Tag(2)).
type tagFQ6 struct {
	Vendor  uint16
	Profile uint16
	TagNum  uint16
}

// Control returns TagCtlFullyQualified6.
func (t tagFQ6) Control() TagControl { return TagFullyQualified6 }

// SerializeTag returns the 6-byte payload.
func (t tagFQ6) SerializeTag() []byte {
	b := make([]byte, 6)
	binary.LittleEndian.PutUint16(b[0:2], t.Vendor)
	binary.LittleEndian.PutUint16(b[2:4], t.Profile)
	binary.LittleEndian.PutUint16(b[4:6], t.TagNum)
	return b
}

// String returns a descriptive representation of the 6-byte fully-qualified tag.
func (t tagFQ6) String() string {
	return fmt.Sprintf("FQ6(V=0x%04X,P=0x%04X,T=0x%04X)", t.Vendor, t.Profile, t.TagNum)
}

// FullyQualified6 constructs a 6-byte fully-qualified tag.
func FullyQualified6(vendor, profile, tagNum uint16) Tag {
	return tagFQ6{Vendor: vendor, Profile: profile, TagNum: tagNum}
}

// tagFQ8 is an 8-byte fully-qualified tag (Vendor(2)+Profile(2)+Tag(4)).
type tagFQ8 struct {
	Vendor  uint16
	Profile uint16
	TagNum  uint32
}

// Control returns TagCtlFullyQualified8.
func (t tagFQ8) Control() TagControl { return TagFullyQualified8 }

// SerializeTag returns the 8-byte payload.
func (t tagFQ8) SerializeTag() []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint16(b[0:2], t.Vendor)
	binary.LittleEndian.PutUint16(b[2:4], t.Profile)
	binary.LittleEndian.PutUint32(b[4:8], t.TagNum)
	return b
}

// String returns a descriptive representation of the 8-byte fully-qualified tag.
func (t tagFQ8) String() string {
	return fmt.Sprintf("FQ8(V=0x%04X,P=0x%04X,T=0x%08X)", t.Vendor, t.Profile, t.TagNum)
}

// FullyQualified8 constructs an 8-byte fully-qualified tag.
func FullyQualified8(vendor, profile uint16, tagNum uint32) Tag {
	return tagFQ8{Vendor: vendor, Profile: profile, TagNum: tagNum}
}

// decodeTagBytes parses raw tag bytes according to the TagControl form.
func decodeTagBytes(tc TagControl, data []byte) (Tag, int, error) {
	switch tc {
	case TagAnonymous:
		return tagAnon{}, 0, nil
	case TagContext:
		if len(data) < 1 {
			return nil, 0, ErrDecodeTagLength
		}
		return tagContext{Num: data[0]}, 1, nil
	case TagCommon2, ImplicitTag2:
		if len(data) < 2 {
			return nil, 0, ErrDecodeTagLength
		}
		val := binary.LittleEndian.Uint16(data[0:2])
		return tagCommon2{Profile: val}, 2, nil
	case TagCommon4, ImplicitTag4:
		if len(data) < 4 {
			return nil, 0, ErrDecodeTagLength
		}
		val := binary.LittleEndian.Uint32(data[0:4])
		return tagCommon4{Value: val}, 4, nil
	case TagFullyQualified6:
		if len(data) < 6 {
			return nil, 0, ErrDecodeTagLength
		}
		v := binary.LittleEndian.Uint16(data[0:2])
		p := binary.LittleEndian.Uint16(data[2:4])
		t := binary.LittleEndian.Uint16(data[4:6])
		return tagFQ6{Vendor: v, Profile: p, TagNum: t}, 6, nil
	case TagFullyQualified8:
		if len(data) < 8 {
			return nil, 0, ErrDecodeTagLength
		}
		v := binary.LittleEndian.Uint16(data[0:2])
		p := binary.LittleEndian.Uint16(data[2:4])
		t := binary.LittleEndian.Uint32(data[4:8])
		return tagFQ8{Vendor: v, Profile: p, TagNum: t}, 8, nil
	default:
		return nil, 0, ErrTagUnsupportedForm
	}
}
