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

package pase

import (
	"bytes"
	"testing"
)

func TestVerifierSerialization(t *testing.T) {
	v, err := NewRandomSaltVerifier(20202021, 1000)
	if err != nil {
		t.Fatal(err)
	}
	b := v.Bytes()
	if len(b) != 97 {
		t.Fatalf("Bytes() is %d bytes, want 97", len(b))
	}
	parsed, err := ParseVerifier(b, v.Salt, v.Iterations)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsed.W0, v.W0) || !bytes.Equal(parsed.L, v.L) {
		t.Fatal("ParseVerifier(Bytes()) differs from the verifier")
	}
	if _, err := ParseVerifier(b[:96], v.Salt, v.Iterations); err == nil {
		t.Fatal("ParseVerifier accepted a short verifier")
	}
	if _, err := ParseVerifier(b, v.Salt[:8], v.Iterations); err == nil {
		t.Fatal("ParseVerifier accepted a short salt")
	}
}
