// Copyright (C) 2025 The go-matter Authors. All rights reserved.
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

import "testing"

func TestSessionKeysReturnsCopies(t *testing.T) {
	i2rKey := []byte{0x01, 0x02, 0x03}
	r2iKey := []byte{0x04, 0x05, 0x06}
	attestationChallenge := []byte{0x07, 0x08, 0x09}

	keys := newSessionKeys(i2rKey, r2iKey, attestationChallenge)

	i2rKey[0] = 0xff
	r2iKey[0] = 0xff
	attestationChallenge[0] = 0xff

	gotI2RKey := keys.I2RKey()
	if gotI2RKey[0] != 0x01 {
		t.Fatalf("I2RKey() returned aliased constructor input: got 0x%02x", gotI2RKey[0])
	}
	gotI2RKey[0] = 0xff
	if got := keys.I2RKey()[0]; got != 0x01 {
		t.Fatalf("I2RKey() returned aliased internal state: got 0x%02x", got)
	}

	gotR2IKey := keys.R2IKey()
	if gotR2IKey[0] != 0x04 {
		t.Fatalf("R2IKey() returned aliased constructor input: got 0x%02x", gotR2IKey[0])
	}
	gotR2IKey[0] = 0xff
	if got := keys.R2IKey()[0]; got != 0x04 {
		t.Fatalf("R2IKey() returned aliased internal state: got 0x%02x", got)
	}

	gotAttestationChallenge := keys.AttestationChallenge()
	if gotAttestationChallenge[0] != 0x07 {
		t.Fatalf("AttestationChallenge() returned aliased constructor input: got 0x%02x", gotAttestationChallenge[0])
	}
	gotAttestationChallenge[0] = 0xff
	if got := keys.AttestationChallenge()[0]; got != 0x07 {
		t.Fatalf("AttestationChallenge() returned aliased internal state: got 0x%02x", got)
	}
}
