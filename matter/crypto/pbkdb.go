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
	"crypto/pbkdf2"
	"crypto/sha256"
)

// 3.9. Password-Based Key Derivation Function (PBKDF).
const (
	PBKDBFIterationsMin = 1000
	PBKDBFIterationsMax = 100000
	PBKDBFSaltMin       = 16
	PBKDBFSaltMax       = 32
)

// CryptoPBKDF implements PBKDF2 as per RFC 2898
// 3.9. Password-Based Key Derivation Function (PBKDF).
func CryptoPBKDF(input []byte, salt []byte, iterations, kLen int) ([]byte, error) {
	// Crypto_PBKDF(input, salt, iterations, len) :=
	//   bit[len] PBKDF2(P := input, S := salt, C := iterations, kLen := len)
	return pbkdf2.Key(sha256.New, string(input), salt, iterations, kLen)
}
