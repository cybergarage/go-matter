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
	"crypto/ecdsa"
	"crypto/rand"
	"math/big"
)

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

func (s *sig) Bytes() []byte {
	// 3) Encode the signature as a byte slice (r || s).
	return append(s.r, s.s...)
}

// CryptoSign computes the digital signature of a message using a given private key.
// 3.5.3.1. Signature.
func CryptoSign(privateKey PrivateKey, message []byte) (Signature, error) {
	// Crypto_Sign(privateKey, message) :=
	// Signature ECDSASign(dU := privateKey, M := message)
	return ECDSASign(privateKey, message)
}

// ECDSASign() SHALL be the ECDSA signature function as defined in Section 4.1 of SEC 1 using Crypto_Hash() as the underlying hash Hash() function.
func ECDSASign(privKey PrivateKey, message []byte) (Signature, error) {
	// 1) Hash the message using Crypto_Hash.
	hashed := CryptoHash(message)
	// 2) Sign the hashed message using ECDSA with the given private key.
	privateKey, ok := privKey.(*privateKey)
	if !ok {
		return nil, newErrInvalid("private key")
	}
	r, s, err := ecdsa.Sign(rand.Reader, privateKey.PrivateKey, hashed)
	if err != nil {
		return nil, err
	}
	return (&sig{
		r: r.Bytes(),
		s: s.Bytes(),
	}), nil
}

// CryptoVerify verifies the digital signature of a message using a given public key.
// 3.5.3.2. Signature verification.
func CryptoVerify(pubKey PublicKey, message []byte, sig Signature) bool {
	// Crypto_Verify(publicKey, message, signature) :=
	// boolean ECDSAVerify(QU := publicKey, M := message, S := signature)
	return ECDSAVerify(pubKey, message, sig)
}

func ECDSAVerify(pubKey PublicKey, message []byte, sig Signature) bool {
	// 1) Hash the message using Crypto_Hash.
	hashed := CryptoHash(message)
	// 2) Verify the signature using ECDSA with the given public key.
	v, ok := pubKey.(*publicKey)
	if !ok {
		return false
	}

	r := sig.R()
	s := sig.S()
	return ecdsa.Verify(v.PublicKey, hashed, new(big.Int).SetBytes(r), new(big.Int).SetBytes(s))
}
