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
	"crypto/elliptic"
	"crypto/rand"
)

// PrivateKey represents a private key used in cryptographic operations.
type PrivateKey interface {
	// Bytes returns the byte representation of the private key.
	Bytes() ([]byte, error)
}

type privateKey struct {
	*ecdsa.PrivateKey
}

// PublicKey represents a public key used in cryptographic operations.
type PublicKey interface {
	// Bytes returns the byte representation of the public key.
	Bytes() ([]byte, error)
}

type publicKey struct {
	*ecdsa.PublicKey
}

// KeyPair represents a pair of public and private keys used in cryptographic operations.
// 3.5. Public Key Cryptography.
type KeyPair interface {
	Public() PublicKey
	Private() PrivateKey
}

type keypair struct {
	prv *privateKey
	pub *publicKey
}

func (k *keypair) Public() PublicKey {
	return k.pub
}

func (k *keypair) Private() PrivateKey {
	return k.prv
}

// CryptoGenerateKeyPair generates a new key pair for use in cryptographic operations.
// 3.5.2. Key generation.
func CryptoGenerateKeyPair() (KeyPair, error) {
	// Crypto_GenerateKeypair() :=
	// KeyPair ECCGenerateKeypair()
	return ECCGenerateKeypair()
}

// ECCGenerateKeypair() SHALL generate a key pair according to Section 3.2.1 of SEC 1.
// 3.5.2. Key generation.
func ECCGenerateKeypair() (KeyPair, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &keypair{
		prv: &privateKey{
			PrivateKey: priv,
		},
		pub: &publicKey{
			PublicKey: &priv.PublicKey,
		},
	}, nil
}
