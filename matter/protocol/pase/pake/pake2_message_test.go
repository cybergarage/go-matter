// Copyright (C) 2026 The go-matter Authors. All rights reserved.
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

package pake

import (
	"bytes"
	"testing"
)

func TestNewPake2MessagePrecomputed(t *testing.T) {
	pB := bytes.Repeat([]byte{0x04}, 65)
	cB := bytes.Repeat([]byte{0xCB}, 32)
	msg, err := NewPake2Message(WithPake2MessagePrecomputed(pB, cB))
	if err != nil {
		t.Fatalf("NewPake2Message(...) error = %v", err)
	}
	b, err := msg.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := NewPake2MessageFromBytes(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.PB(), pB) || !bytes.Equal(decoded.CB(), cB) {
		t.Fatalf("decoded (pB, cB) = (%x, %x), want (%x, %x)", decoded.PB(), decoded.CB(), pB, cB)
	}

	if _, err := NewPake2Message(WithPake2MessagePrecomputed(pB, nil)); err == nil {
		t.Error("NewPake2Message with an empty cB = nil error, want an error")
	}
}
