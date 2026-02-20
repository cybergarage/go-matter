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
	_ = enc.PutUnsigned(NewCommon2Tag(0x3344), 255)
	_ = enc.PutUnsigned(NewCommon4Tag(0xAABBCCDD), 1024)
	_ = enc.PutUnsigned(NewFullyQualified6(0x1234, 0x5678, 0x9ABC), 77)
	_ = enc.PutUnsigned(NewFullyQualified8(0x1357, 0x2468, 0x90ABCDEF), 88)

	// Containers
	enc.BeginStructure(NewContextTag(12))
	_ = enc.PutUnsigned(NewAnonymousTag(), 1)
	enc.BeginArray(NewContextTag(13))
	_ = enc.PutUnsigned(NewAnonymousTag(), 2)
	_ = enc.PutUnsigned(NewAnonymousTag(), 3)
	enc.EndContainer() // array
	enc.BeginList(NewContextTag(14))
	_ = enc.PutSigned(NewAnonymousTag(), -1)
	_ = enc.PutSigned(NewAnonymousTag(), -2)
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
	enc.BeginStructure(NewAnonymousTag())
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
	enc.PutBool(NewAnonymousTag(), false)
	enc.PutBool(NewAnonymousTag(), true)
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

func TestPutSignedUnsignedVariants(t *testing.T) {
	enc := NewEncoder()

	// Signed ints
	if err := enc.PutSigned1(NewContextTag(1), int8(-128)); err != nil {
		t.Fatalf("PutSigned1 failed: %v", err)
	}
	if err := enc.PutSigned2(NewContextTag(2), int16(-32768)); err != nil {
		t.Fatalf("PutSigned2 failed: %v", err)
	}
	if err := enc.PutSigned4(NewContextTag(3), int32(-2147483648)); err != nil {
		t.Fatalf("PutSigned4 failed: %v", err)
	}
	if err := enc.PutSigned8(NewContextTag(4), int64(-9223372036854775808)); err != nil {
		t.Fatalf("PutSigned8 failed: %v", err)
	}

	// Unsigned ints
	if err := enc.PutUnsigned1(NewContextTag(5), uint8(255)); err != nil {
		t.Fatalf("PutUnsigned1 failed: %v", err)
	}
	if err := enc.PutUnsigned2(NewContextTag(6), uint16(65535)); err != nil {
		t.Fatalf("PutUnsigned2 failed: %v", err)
	}
	if err := enc.PutUnsigned4(NewContextTag(7), uint32(4294967295)); err != nil {
		t.Fatalf("PutUnsigned4 failed: %v", err)
	}
	if err := enc.PutUnsigned8(NewContextTag(8), uint64(18446744073709551615)); err != nil {
		t.Fatalf("PutUnsigned8 failed: %v", err)
	}

	enc.MustEndAll()
	data := enc.Bytes()

	dec := NewDecoderWithBytes(data)
	var tagsSeen []ContextNumber
	for dec.Next() {
		elem := dec.Element()
		ctx, ok := elem.Tag().(ContextTag)
		if !ok {
			t.Errorf("Expected ContextTag, got %T", elem.Tag())
			continue
		}
		tagsSeen = append(tagsSeen, ctx.ContextNumber())
	}
	if len(tagsSeen) != 8 {
		t.Errorf("Expected 8 elements, got %d", len(tagsSeen))
	}
	tagsSum := 0
	for _, ctxNum := range tagsSeen {
		tagsSum += int(ctxNum)
	}
	if tagsSum != 36 {
		t.Errorf("Expected sum of context numbers to be 36, got %d", tagsSum)
	}
}
