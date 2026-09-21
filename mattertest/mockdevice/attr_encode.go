// Copyright (C) 2026 The go-matter Authors. All rights reserved.
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

package mockdevice

import "github.com/cybergarage/go-matter/matter/encoding/tlv"

// boolAttribute/uint8Attribute/uint16Attribute/uint32Attribute/utf8Attribute
// build the readHandler-shaped encoder for a scalar attribute value, each
// writing it as the Data element (ContextTag(2)) of an AttributeDataIB
// (10.6.3).
func boolAttribute(v bool) func(enc tlv.Encoder) error {
	return func(enc tlv.Encoder) error {
		enc.PutBool(tlv.NewContextTag(2), v)
		return nil
	}
}

func uint8Attribute(v uint8) func(enc tlv.Encoder) error {
	return func(enc tlv.Encoder) error {
		enc.PutUnsigned1(tlv.NewContextTag(2), v)
		return nil
	}
}

func uint16Attribute(v uint16) func(enc tlv.Encoder) error {
	return func(enc tlv.Encoder) error {
		enc.PutUnsigned2(tlv.NewContextTag(2), v)
		return nil
	}
}

func uint32Attribute(v uint32) func(enc tlv.Encoder) error {
	return func(enc tlv.Encoder) error {
		enc.PutUnsigned4(tlv.NewContextTag(2), v)
		return nil
	}
}

func utf8Attribute(v string) func(enc tlv.Encoder) error {
	return func(enc tlv.Encoder) error {
		return enc.PutUTF8(tlv.NewContextTag(2), v)
	}
}

// nullAttribute builds the readHandler-shaped encoder for a nullable
// attribute's null value.
func nullAttribute() func(enc tlv.Encoder) error {
	return func(enc tlv.Encoder) error {
		enc.PutNull(tlv.NewContextTag(2))
		return nil
	}
}

// listAttribute wraps encodeItems — which must emit zero or more
// anonymously-tagged elements, one per list item, matching how
// im.ReadListAttribute's itemFn decodes them — in the Array container a
// List-typed attribute's Data element (ContextTag(2)) requires.
func listAttribute(encodeItems func(enc tlv.Encoder) error) func(enc tlv.Encoder) error {
	return func(enc tlv.Encoder) error {
		enc.BeginArray(tlv.NewContextTag(2))
		if err := encodeItems(enc); err != nil {
			return err
		}
		return enc.EndContainer()
	}
}

// chunkedListItemAttribute writes a single list item directly as the Data
// element (ContextTag(2)) — not wrapped in an Array — for use as one of a
// chunked list's later "append" reports (10.5.4.3, "List Chunking"; see
// imServer.sendReadDataChunked). encodeFields must emit the item's own
// contents (e.g. a Structure's fields) without its own outer tag.
func chunkedListItemAttribute(encodeFields func(enc tlv.Encoder) error) func(enc tlv.Encoder) error {
	return func(enc tlv.Encoder) error {
		enc.BeginStructure(tlv.NewContextTag(2))
		if err := encodeFields(enc); err != nil {
			return err
		}
		return enc.EndContainer()
	}
}
