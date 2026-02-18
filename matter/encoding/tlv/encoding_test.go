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
	"bytes"
	"encoding/hex"
	"testing"
)

// TestRoundTrip exercises multiple element variants, tag forms, and container nesting.
func TestRoundTrip(t *testing.T) {
	enc := NewEncoder()

	// Unsigned small -> ETUnsignedInt1
	_ = enc.PutUnsigned(NewContextTag(1), 42)
	// Signed fits in 2 bytes -> ETSignedInt2
	_ = enc.PutSigned(NewContextTag(2), -300)
	// Large unsigned -> ETUnsignedInt8
	_ = enc.PutUnsigned(NewContextTag(3), 1<<40)
	// Bool false/true
	enc.PutBool(NewContextTag(4), false)
	enc.PutBool(NewContextTag(5), true)
	// Null
	enc.PutNull(NewContextTag(6))
	// Floats
	enc.PutFloat32(NewContextTag(7), 3.14)
	enc.PutFloat64(NewContextTag(8), -6.28)
	// UTF-8 short
	if err := enc.PutUTF8(NewContextTag(9), "Hello"); err != nil {
		t.Fatalf("PutUTF8 short: %v", err)
	}
	// UTF-8 longer (force 2-byte length)
	longStr := make([]byte, 300)
	for i := range longStr {
		longStr[i] = 'A'
	}
	if err := enc.PutUTF8(NewContextTag(10), string(longStr)); err != nil {
		t.Fatalf("PutUTF8 long: %v", err)
	}
	// Byte string
	if err := enc.PutBytes(NewContextTag(11), []byte{0xDE, 0xAD, 0xBE, 0xEF}); err != nil {
		t.Fatalf("PutBytes: %v", err)
	}

	// Various tag forms
	_ = enc.PutUnsigned(Common2Tag(0x3344), 255)
	_ = enc.PutUnsigned(Common4Tag(0xAABBCCDD), 1024)
	_ = enc.PutUnsigned(FullyQualified6(0x1234, 0x5678, 0x9ABC), 77)
	_ = enc.PutUnsigned(FullyQualified8(0x1357, 0x2468, 0x90ABCDEF), 88)

	// Containers
	enc.StartStructure(NewContextTag(12))
	_ = enc.PutUnsigned(AnonymousTag(), 1)
	enc.StartArray(NewContextTag(13))
	_ = enc.PutUnsigned(AnonymousTag(), 2)
	_ = enc.PutUnsigned(AnonymousTag(), 3)
	enc.EndContainer() // array
	enc.StartList(NewContextTag(14))
	_ = enc.PutSigned(AnonymousTag(), -1)
	_ = enc.PutSigned(AnonymousTag(), -2)
	enc.EndContainer() // list
	enc.EndContainer() // structure

	enc.MustEndAll()

	raw := enc.Bytes()
	if len(raw) == 0 {
		t.Fatalf("encoded buffer empty")
	}

	// Simple smoke decode pass
	dec := NewDecoderWithBytes(raw)
	var out bytes.Buffer
	count := 0
	for dec.Next() {
		out.WriteString(dec.Element().String())
		out.WriteByte('\n')
		count++
	}
	if dec.Error() != nil {
		t.Fatalf("decode error: %v\nEncoded=%s", dec.Error(), hex.EncodeToString(raw))
	}
	if count == 0 {
		t.Fatalf("no elements decoded")
	}
}

func TestContainerMismatch(t *testing.T) {
	enc := NewEncoder()
	enc.StartStructure(AnonymousTag())
	// Missing EndContainer intentionally
	raw := enc.Bytes()

	dec := NewDecoderWithBytes(raw)
	for dec.Next() {
	}
	if dec.Error() == nil {
		t.Fatalf("expected error for unclosed container")
	}
}

func TestBooleanVariants(t *testing.T) {
	enc := NewEncoder()
	enc.PutBool(AnonymousTag(), false)
	enc.PutBool(AnonymousTag(), true)
	data := enc.Bytes()

	dec := NewDecoderWithBytes(data)
	var vals []bool
	for dec.Next() {
		if b, ok := dec.Element().Bool(); ok {
			vals = append(vals, b)
		}
	}
	if dec.Error() != nil {
		t.Fatalf("decode err: %v", dec.Error())
	}
	if len(vals) != 2 || vals[0] != false || vals[1] != true {
		t.Fatalf("unexpected bool sequence: %#v", vals)
	}
}
