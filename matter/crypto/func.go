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

package crypto

import (
	"crypto/rand"
	"crypto/sha256"
)

// Crypto_DRBG is a placeholder function for a deterministic random bit generator (DRBG) used in cryptographic operations.
// 3.1. Deterministic Random Bit Generator (DRBG).
func Crypto_DRBG(l int) []byte { // nolint:staticcheck
	// Crypto_DRBG() SHALL be seeded and reseeded using Crypto_TRNG() with at least 256 bits of entropy
	// (see among others Chapter 4, Section 8.4, and Section 8.6.8 of NIST 800-90A).
	seed := Crypto_TRNG(32) // 256 bits of entropy for seeding
	out := make([]byte, l)
	n, err := rand.Read(out)
	if err != nil || n != l {
		return nil
	}
	// Crypto_DRBG() SHALL be implemented with one of the following DRBG algorithms as defined in　NIST 800-90A.
	bytes := make([]byte, 0, l)
	for len(bytes) < l {
		hash := sha256.Sum256(seed)
		remain := l - len(bytes)
		if remain >= len(hash) {
			bytes = append(bytes, hash[:]...)
		} else {
			bytes = append(bytes, hash[:remain]...)
		}
		seed = hash[:] // Update seed for next iteration
	}
	return bytes[:l]
}

// Crypto_TRNG is a placeholder function for a true random number generator (TRNG) used in cryptographic operations.
// 3.2. True Random Number Generator (TRNG).
func Crypto_TRNG(l int) []byte { // nolint:staticcheck
	// Crypto_TRNG() MAY be implemented according to the NIST 800-90B implementation guidelines but
	// alternate implementations MAY be used.
	out := make([]byte, l)
	n, err := rand.Read(out)
	if err != nil || n != l {
		// In a real implementation, handle error securely (e.g., panic or return nil)
		return nil
	}
	return out
}
