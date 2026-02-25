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
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
)

// CryptoDRBG is a placeholder function for a deterministic random bit generator (DRBG) used in cryptographic operations.
// 3.1. Deterministic Random Bit Generator (DRBG).
func CryptoDRBG(l int) []byte {
	// Crypto_DRBG() SHALL be seeded and reseeded using Crypto_TRNG() with at least 256 bits of entropy
	// (see among others Chapter 4, Section 8.4, and Section 8.6.8 of NIST 800-90A).
	seed := CryptoTRNG(32) // 256 bits of entropy for seeding
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

// CryptoTRNG is a placeholder function for a true random number generator (TRNG) used in cryptographic operations.
// 3.2. True Random Number Generator (TRNG).
func CryptoTRNG(l int) []byte {
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

// CryptoHash computes the cryptographic hash of a message.
// 3.3. Hash function (Hash).
func CryptoHash(message []byte) []byte {
	// Crypto_Hash(message) :=
	//   byte[CRYPTO_HASH_LEN_BYTES] SHA-256(M := message)
	hash := sha256.Sum256(message)
	return hash[:CryptoHashLenBytes]
}

// CryptoHMAC computes the keyed-hash message authentication code (HMAC) of a message using a given key.
// 3.4. Keyed-Hash Message Authentication Code (HMAC).
func CryptoHMAC(key []byte, message []byte) []byte {
	// 	Crypto_HMAC(key, message) :=
	// byte[CRYPTO_HASH_LEN_BYTES] HMAC(K := key, text := message)
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return mac.Sum(nil)[:CryptoHashLenBytes]
}

// CryptoPBKDF computes the password-based key derivation function (PBKDF) of a password using a given salt and iteration count.
// 3.9. Password-Based Key Derivation Function (PBKDF).
func CryptoPBKDF(input []byte, salt []byte, iterations int, length int) ([]byte, error) {
	return pbkdf2.Key(sha256.New, string(input), salt, iterations, length)
}
