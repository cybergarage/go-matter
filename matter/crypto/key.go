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
	"math/big"
)

// PrivateKey represents a private key used in cryptographic operations.
type PrivateKey *big.Int

// PublicKey represents a public key used in cryptographic operations.
type PublicKey interface {
	X() *big.Int
	Y() *big.Int
}

type publicKey struct {
	x, y *big.Int
}

func (p *publicKey) X() *big.Int {
	return p.x
}

func (p *publicKey) Y() *big.Int {
	return p.y
}

// KeyPair represents a pair of public and private keys used in cryptographic operations.
// 3.5. Public Key Cryptography.
type KeyPair interface {
	Public() PublicKey
	Private() PrivateKey
}

type keypair struct {
	priv *ecdsa.PrivateKey
	pub  publicKey
}

func (k *keypair) Public() PublicKey {
	return &k.pub
}

func (k *keypair) Private() PrivateKey {
	return k.priv.D
}

// CryptoGenerateKeypair generates a new key pair for use in cryptographic operations.
// 3.5.2. Key generation.
func CryptoGenerateKeypair() (KeyPair, error) {
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
		priv: priv,
		pub: publicKey{
			x: priv.PublicKey.X,
			y: priv.PublicKey.Y,
		},
	}, nil
}
