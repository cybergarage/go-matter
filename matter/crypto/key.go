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

import "crypto/ecdsa"

// PrivateKey represents a private key used in cryptographic operations.
type PrivateKey interface {
	// Bytes returns the byte representation of the private key.
	Bytes() ([]byte, error)
}

// PublicKey represents a public key used in cryptographic operations.
type PublicKey interface {
	// Bytes returns the byte representation of the public key.
	Bytes() ([]byte, error)
}

// KeyPair represents a pair of public and private keys used in cryptographic operations.
// 3.5. Public Key Cryptography.
type KeyPair interface {
	Public() PublicKey
	Private() PrivateKey
}

// CryptoGenerateKeyPair generates a new key pair for use in cryptographic operations.
// 3.5.2. Key generation.
func CryptoGenerateKeyPair() (KeyPair, error) {
	// Crypto_GenerateKeypair() :=
	// KeyPair ECCGenerateKeypair()
	return ECCGenerateKeypair()
}

// NewPublicKey wraps a standard library ECDSA public key (for example one
// extracted from an *x509.Certificate) so it can be passed to this package's
// Crypto_* primitives (CryptoVerify, ECDSAVerify). Those functions only
// accept PublicKey values created by this package's own constructors.
func NewPublicKey(pub *ecdsa.PublicKey) PublicKey {
	return &publicKey{PublicKey: pub}
}

// NewPrivateKey wraps a standard library ECDSA private key so it can be
// passed to this package's Crypto_* primitives (CryptoSign, ECDSASign).
// Those functions only accept PrivateKey values created by this package's
// own constructors.
func NewPrivateKey(priv *ecdsa.PrivateKey) PrivateKey {
	return &privateKey{PrivateKey: priv}
}
