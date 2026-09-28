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
	"fmt"

	"github.com/cybergarage/go-matter/matter/crypto"
)

// Verifier is what a PASE responder holds instead of the passcode: the
// SPAKE2+ verifier (w0, L) together with the PBKDF salt and iteration count
// it was derived with (Matter Core 3.10). A device is typically provisioned
// with a verifier at the factory, so the passcode itself never has to be
// stored on it; NewVerifier derives one from a passcode for devices, tests
// and tools that do have it.
type Verifier struct {
	// W0 is the 32-byte scalar w0.
	W0 []byte
	// L is the 65-byte uncompressed point L = w1·P.
	L []byte
	// Salt is the PBKDF salt, 16 to 32 bytes.
	Salt []byte
	// Iterations is the PBKDF iteration count, 1000 to 100000.
	Iterations int
}

// NewVerifier derives the Verifier for passcode with the given salt and
// iteration count.
func NewVerifier(passcode Passcode, salt []byte, iterations int) (Verifier, error) {
	v := Verifier{W0: nil, L: nil, Salt: salt, Iterations: iterations}
	if err := v.validateParams(); err != nil {
		return Verifier{}, err
	}
	w0, l, err := crypto.CryptoPAKEValuesResponder(passcode.Bytes(), salt, iterations)
	if err != nil {
		return Verifier{}, fmt.Errorf("pase: derive verifier: %w", err)
	}
	v.W0 = w0
	v.L = l
	return v, nil
}

// NewRandomSaltVerifier derives the Verifier for passcode with a fresh random
// salt of the maximum length and the given iteration count.
func NewRandomSaltVerifier(passcode Passcode, iterations int) (Verifier, error) {
	return NewVerifier(passcode, crypto.CryptoTRNG(crypto.PBKDBFSaltMax), iterations)
}

// Validate reports whether v holds values a responder can use.
func (v Verifier) Validate() error {
	if err := v.validateParams(); err != nil {
		return err
	}
	if len(v.W0) != crypto.CryptoGroupSizeBytes {
		return fmt.Errorf("pase: verifier w0 is %d bytes, want %d", len(v.W0), crypto.CryptoGroupSizeBytes)
	}
	if len(v.L) != crypto.CryptoPublicKeySizeBytes {
		return fmt.Errorf("pase: verifier L is %d bytes, want %d", len(v.L), crypto.CryptoPublicKeySizeBytes)
	}
	return nil
}

func (v Verifier) validateParams() error {
	if n := len(v.Salt); n < crypto.PBKDBFSaltMin || n > crypto.PBKDBFSaltMax {
		return fmt.Errorf("pase: salt is %d bytes, want %d..%d", n, crypto.PBKDBFSaltMin, crypto.PBKDBFSaltMax)
	}
	if v.Iterations < crypto.PBKDBFIterationsMin || v.Iterations > crypto.PBKDBFIterationsMax {
		return fmt.Errorf("pase: %d PBKDF iterations, want %d..%d", v.Iterations, crypto.PBKDBFIterationsMin, crypto.PBKDBFIterationsMax)
	}
	return nil
}
