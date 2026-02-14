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

package pbkdf

import (
	"hash"
)

// Parameters for PBKDF operations, as defined by the Matter specification. These.
type Params interface {
	// Password returns the password (e.g., the pairing code) used for PBKDF key derivation.
	Password() []byte
	// Salt returns the salt value used for PBKDF key derivation.
	Salt() []byte
	// Iterations returns the number of iterations used for PBKDF key derivation.
	Iterations() int
	// KeyLength returns the desired length of the derived key in bytes.
	KeyLength() int
	// Hash returns the hash function to be used for PBKDF key derivation.
	Hash() hash.Hash
}
