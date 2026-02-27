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

var (
	ellipticCurve = elliptic.P256()
)

type privateKey struct {
	*ecdsa.PrivateKey
}

type publicKey struct {
	*ecdsa.PublicKey
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

// ECCGenerateKeypair() SHALL generate a key pair according to Section 3.2.1 of SEC 1.
// 3.5.2. Key generation.
func ECCGenerateKeypair() (KeyPair, error) {
	priv, err := ecdsa.GenerateKey(ellipticCurve, rand.Reader)
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

// ECDSAVerify() SHALL be the ECDSA signature verification function as defined in Section 4.1 of SEC 1 using Crypto_Hash() as the underlying hash Hash() function.
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
