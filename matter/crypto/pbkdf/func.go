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
	"golang.org/x/crypto/pbkdf2"
)

// CryptoPBKDF implements PBKDF2 as per RFC 2898
// 3.9. Password-Based Key Derivation Function (PBKDF).
func CryptoPBKDF(p Params) ([]byte, error) {
	password, ok := p.Password()
	if !ok {
		return nil, newErrMissingRequiredField("password")
	}
	salt, ok := p.Salt()
	if !ok {
		return nil, newErrMissingRequiredField("salt")
	}
	iterations, ok := p.Iterations()
	if !ok {
		return nil, newErrMissingRequiredField("iterations")
	}
	keyLength, ok := p.KeyLength()
	if !ok {
		return nil, newErrMissingRequiredField("keyLength")
	}
	return pbkdf2.Key(password, salt, iterations, keyLength, p.Hash), nil
}
