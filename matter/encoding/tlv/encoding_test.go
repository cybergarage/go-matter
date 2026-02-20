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
	if err := enc.PutOctet(NewContextTag(11), []byte{0xDE, 0xAD, 0xBE, 0xEF}); err != nil {
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
	enc.PutSigned1(NewContextTag(1), int8(-128))
	enc.PutSigned2(NewContextTag(2), int16(-32768))
	enc.PutSigned4(NewContextTag(3), int32(-2147483648))
	enc.PutSigned8(NewContextTag(4), int64(-9223372036854775808))

	// Unsigned ints
	enc.PutUnsigned1(NewContextTag(5), uint8(255))
	enc.PutUnsigned2(NewContextTag(6), uint16(65535))
	enc.PutUnsigned4(NewContextTag(7), uint32(4294967295))
	enc.PutUnsigned8(NewContextTag(8), uint64(18446744073709551615))

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

func TestPutUTF8Variants(t *testing.T) {
	tests := []struct {
		name    string
		putFunc func(enc Encoder, tag Tag, s string) error
		tag     Tag
		str     string
	}{
		{
			name:    "UTF8_1",
			putFunc: func(enc Encoder, tag Tag, s string) error { return enc.PutUTF81(tag, s) },
			tag:     NewContextTag(1),
			str:     "abc",
		},
		{
			name:    "UTF8_2",
			putFunc: func(enc Encoder, tag Tag, s string) error { return enc.PutUTF82(tag, s) },
			tag:     NewContextTag(2),
			str:     string(bytes.Repeat([]byte{'x'}, 300)), // >255 to force 2-byte length
		},
		{
			name:    "UTF8_4",
			putFunc: func(enc Encoder, tag Tag, s string) error { return enc.PutUTF84(tag, s) },
			tag:     NewContextTag(3),
			str:     string(bytes.Repeat([]byte{'y'}, 70000)), // >65535 to force 4-byte length
		},
		{
			name:    "UTF8_8",
			putFunc: func(enc Encoder, tag Tag, s string) error { return enc.PutUTF88(tag, s) },
			tag:     NewContextTag(4),
			str:     string(bytes.Repeat([]byte{'z'}, 100000)), // Large, but not huge for test
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc := NewEncoder()
			err := tt.putFunc(enc, tt.tag, tt.str)
			if err != nil {
				t.Fatalf("PutUTF8 variant failed: %v", err)
			}
			enc.MustEndAll()
			raw := enc.Bytes()
			dec := NewDecoderWithBytes(raw)
			found := false
			for dec.Next() {
				elem := dec.Element()
				if elem.Tag().String() == tt.tag.String() {
					s, ok := elem.UTF8()
					if !ok {
						t.Fatalf("Decoded element is not UTF8")
					}
					if s != tt.str {
						t.Fatalf("Decoded UTF8 mismatch: got %q, want %q", s, tt.str)
					}
					found = true
				}
			}
			if dec.Error() != nil {
				t.Fatalf("Decode error: %v", dec.Error())
			}
			if !found {
				t.Fatalf("UTF8 element not found for tag %v", tt.tag)
			}
		})
	}
}

func TestPutOctetVariants(t *testing.T) {
	tests := []struct {
		name    string
		putFunc func(enc Encoder, tag Tag, b []byte) error
		tag     Tag
		data    []byte
	}{
		{
			name:    "Octet1",
			putFunc: func(enc Encoder, tag Tag, b []byte) error { return enc.PutOctet1(tag, b) },
			tag:     NewContextTag(1),
			data:    []byte{0x01, 0x02, 0x03},
		},
		{
			name:    "Octet2",
			putFunc: func(enc Encoder, tag Tag, b []byte) error { return enc.PutOctet2(tag, b) },
			tag:     NewContextTag(2),
			data:    []byte{0xAA, 0xBB, 0xCC, 0xDD},
		},
		{
			name:    "Octet4",
			putFunc: func(enc Encoder, tag Tag, b []byte) error { return enc.PutOctet4(tag, b) },
			tag:     NewContextTag(3),
			data:    []byte{0x10, 0x20, 0x30, 0x40, 0x50, 0x60},
		},
		{
			name:    "Octet8",
			putFunc: func(enc Encoder, tag Tag, b []byte) error { return enc.PutOctet8(tag, b) },
			tag:     NewContextTag(4),
			data:    []byte{0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc := NewEncoder()
			err := tt.putFunc(enc, tt.tag, tt.data)
			if err != nil {
				t.Fatalf("PutOctet variant failed: %v", err)
			}
			enc.MustEndAll()
			raw := enc.Bytes()
			dec := NewDecoderWithBytes(raw)
			found := false
			for dec.Next() {
				elem := dec.Element()
				if elem.Tag().String() == tt.tag.String() {
					b, ok := elem.Bytes()
					if !ok {
						t.Fatalf("Decoded element is not octet")
					}
					if !bytes.Equal(b, tt.data) {
						t.Fatalf("Decoded octet mismatch: got %x, want %x", b, tt.data)
					}
					found = true
				}
			}
			if dec.Error() != nil {
				t.Fatalf("Decode error: %v", dec.Error())
			}
			if !found {
				t.Fatalf("Octet element not found for tag %v", tt.tag)
			}
		})
	}
}
