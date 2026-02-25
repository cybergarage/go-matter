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

// Signature represents a digital signature used in cryptographic operations.
// 3.5.3. Signature and verification.
type Signature interface {
	R() []byte
	S() []byte
}

type sig struct {
	r []byte
	s []byte
}

func (s *sig) R() []byte {
	return s.r
}

func (s *sig) S() []byte {
	return s.s
}

// CryptoSign computes the digital signature of a message using a given private key.
// 3.5.3.1. Signature.
func CryptoSign(privateKey PrivateKey, message []byte) ([]byte, error) {
	// Crypto_Sign(privateKey, message) :=
	// Signature ECDSASign(dU := privateKey, M := message)
	return nil, nil
	// return ECDSASign(privateKey, message)
}

// ECDSASign() SHALL be the ECDSA signature function as defined in Section 4.1 of SEC 1 using Crypto_Hash() as the underlying hash Hash() function.
// func ECDSASign(privateKey PrivateKey, message []byte) ([]byte, error) {
// 	// 1) Hash the message using Crypto_Hash.
// 	hashed := CryptoHash(message)
// 	// 2) Sign the hashed message using ECDSA with the given private key.
// 	r, s, err := ecdsa.Sign(rand.Reader, (*ecdsa.PrivateKey)(privateKey), hashed)
// 	if err != nil {
// 		return nil, err
// 	}
// 	// 3) Encode the signature as a byte slice (r || s).
// 	signature := append(r.Bytes(), s.Bytes()...)
// 	return signature, nil
// }
