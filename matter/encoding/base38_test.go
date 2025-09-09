// Copyright (C) 2025 The go-matter Authors. All rights reserved.
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

package encoding

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestRoundTrip_ShortLengths(t *testing.T) {
	cases := [][]byte{
		{},                             // empty
		{0x00},                         // 1 byte
		{0xAB},                         // 1 byte
		{0x01, 0x02},                   // 2 bytes
		{0xFF, 0x00},                   // 2 bytes
		{0xDE, 0xAD, 0xBE},             // 3 bytes
		{0xDE, 0xAD, 0xBE, 0xEF},       // 4 bytes
		{0x00, 0x11, 0x22, 0x33, 0x44}, // 5 bytes
	}

	for _, src := range cases {
		enc := EncodeBase38(src)
		dec, err := DecodeBase38(enc)
		if err != nil {
			t.Fatalf("decode error: %v", err)
		}
		if !bytes.Equal(src, dec) {
			t.Fatalf("mismatch\nsrc=% X\ndec=% X", src, dec)
		}
	}
}

func TestRoundTrip_Random(t *testing.T) {
	for n := 1; n <= 128; n++ {
		buf := make([]byte, n)
		_, _ = rand.Read(buf)
		enc := EncodeBase38(buf)
		dec, err := DecodeBase38(enc)
		if err != nil {
			t.Fatalf("decode error at n=%d: %v", n, err)
		}
		if !bytes.Equal(buf, dec) {
			t.Fatalf("mismatch at n=%d", n)
		}
	}
}
