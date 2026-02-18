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

// Tag represents a TLV tag. It encapsulates the tag control and associated payload bytes, and provides methods for encoding and decoding tags in various forms.
type Tag interface {
	// Control returns the 3-bit TagControl value associated with this tag.
	Control() TagControl
	// Bytes returns the tag payload bytes (may be empty for anonymous).
	Bytes() []byte
	// String returns a human-readable representation of the tag.
	String() string
}

// tagAnon is the anonymous tag implementation (no payload bytes).
type tagAnon struct{}

// AnonymousTag constructs a Tag representing an anonymous tag.
func AnonymousTag() Tag { return tagAnon{} }

// Control returns TagCtlAnonymous.
func (t tagAnon) Control() TagControl { return TagAnonymous }

// Bytes returns nil (anonymous tag has no payload).
func (t tagAnon) Bytes() []byte { return nil }

// String returns a descriptive name for the anonymous tag.
func (t tagAnon) String() string { return "(anon)" }

// tagContext is a context-specific tag with a 1-byte number.
type tagContext struct {
	Num uint8
}

// ContextTag constructs a context-specific tag with the given 1-byte number.
func ContextTag(num uint8) Tag { return tagContext{Num: num} }

// Control returns TagCtlContext.
func (t tagContext) Control() TagControl { return TagContext }

// Bytes returns the single context tag byte.
func (t tagContext) Bytes() []byte { return []byte{t.Num} }

// String returns a descriptive string for the context tag.
func (t tagContext) String() string { return fmt.Sprintf("Context(%d)", t.Num) }

// tagCommon2 is a common/profile form with 2 bytes.
type tagCommon2 struct {
	Profile uint16
}

// Common2Tag constructs a 2-byte common/profile tag.
func Common2Tag(profile uint16) Tag { return tagCommon2{Profile: profile} }

// Control returns TagCtlCommon2.
func (t tagCommon2) Control() TagControl { return TagCommon2 }

// Bytes returns 2 bytes (little-endian).
func (t tagCommon2) Bytes() []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, t.Profile)
	return b
}

// String returns a descriptive representation.
func (t tagCommon2) String() string { return fmt.Sprintf("Common2(0x%04X)", t.Profile) }

// tagCommon4 is a 4-byte common/extended profile tag.
type tagCommon4 struct {
	Value uint32
}

// Common4Tag constructs a 4-byte common/extended tag.
func Common4Tag(val uint32) Tag { return tagCommon4{Value: val} }

// Control returns TagCtlCommon4.
func (t tagCommon4) Control() TagControl { return TagCommon4 }

// Bytes returns the 4-byte little-endian payload.
func (t tagCommon4) Bytes() []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, t.Value)
	return b
}

// String returns a descriptive representation of the 4-byte common tag.
func (t tagCommon4) String() string { return fmt.Sprintf("Common4(0x%08X)", t.Value) }

type tagImplicit2 struct {
	Profile uint16
}

// Implicit2Tag constructs a 2-byte implicit profile tag.
func Implicit2Tag(profile uint16) Tag { return tagImplicit2{Profile: profile} }

// Control returns TagCtlImplicit2.
func (t tagImplicit2) Control() TagControl { return ImplicitTag2 }

// Bytes returns 2 bytes (little-endian).
func (t tagImplicit2) Bytes() []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, t.Profile)
	return b
}

// String returns a descriptive representation.
func (t tagImplicit2) String() string { return fmt.Sprintf("Implicit2(0x%04X)", t.Profile) }

type tagImplicit4 struct {
	Value uint32
}

// Implicit4Tag constructs a 4-byte implicit profile tag.
func Implicit4Tag(val uint32) Tag { return tagImplicit4{Value: val} }

// Control returns TagCtlImplicit4.
func (t tagImplicit4) Control() TagControl { return ImplicitTag4 }

// Bytes returns the 4-byte little-endian payload.
func (t tagImplicit4) Bytes() []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, t.Value)
	return b
}

// String returns a descriptive representation of the 4-byte implicit tag.
func (t tagImplicit4) String() string { return fmt.Sprintf("Implicit4(0x%08X)", t.Value) }

// tagFQ6 is a 6-byte fully-qualified tag (Vendor(2)+Profile(2)+Tag(2)).
type tagFQ6 struct {
	Vendor  uint16
	Profile uint16
	TagNum  uint16
}

// FullyQualified6 constructs a 6-byte fully-qualified tag.
func FullyQualified6(vendor, profile, tagNum uint16) Tag {
	return tagFQ6{Vendor: vendor, Profile: profile, TagNum: tagNum}
}

// Control returns TagCtlFullyQualified6.
func (t tagFQ6) Control() TagControl { return TagFullyQualified6 }

// Bytes returns the 6-byte payload.
func (t tagFQ6) Bytes() []byte {
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

// tagFQ8 is an 8-byte fully-qualified tag (Vendor(2)+Profile(2)+Tag(4)).
type tagFQ8 struct {
	Vendor  uint16
	Profile uint16
	TagNum  uint32
}

// FullyQualified8 constructs an 8-byte fully-qualified tag.
func FullyQualified8(vendor, profile uint16, tagNum uint32) Tag {
	return tagFQ8{Vendor: vendor, Profile: profile, TagNum: tagNum}
}

// Control returns TagCtlFullyQualified8.
func (t tagFQ8) Control() TagControl { return TagFullyQualified8 }

// Bytes returns the 8-byte payload.
func (t tagFQ8) Bytes() []byte {
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
	case TagCommon2:
		if len(data) < 2 {
			return nil, 0, ErrDecodeTagLength
		}
		val := binary.LittleEndian.Uint16(data[0:2])
		return tagCommon2{Profile: val}, 2, nil
	case TagCommon4:
		if len(data) < 4 {
			return nil, 0, ErrDecodeTagLength
		}
		val := binary.LittleEndian.Uint32(data[0:4])
		return tagCommon4{Value: val}, 4, nil
	case ImplicitTag2:
		if len(data) < 2 {
			return nil, 0, ErrDecodeTagLength
		}
		val := binary.LittleEndian.Uint16(data[0:2])
		return tagImplicit2{Profile: val}, 2, nil
	case ImplicitTag4:
		if len(data) < 4 {
			return nil, 0, ErrDecodeTagLength
		}
		val := binary.LittleEndian.Uint32(data[0:4])
		return tagImplicit4{Value: val}, 4, nil
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
