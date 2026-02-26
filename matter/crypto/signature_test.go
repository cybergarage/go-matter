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
	"testing"
)

func TestCryptoSignAndVerify(t *testing.T) {
	// Generate ECDSA key pair
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	privateKey := &privateKey{PrivateKey: priv}
	publicKey := &publicKey{PublicKey: &priv.PublicKey}

	message := []byte("test message")

	// Sign the message
	signature, err := CryptoSign(privateKey, message)
	if err != nil {
		t.Fatalf("CryptoSign failed: %v", err)
	}

	// Verify the signature
	valid := CryptoVerify(publicKey, message, signature)
	if !valid {
		t.Errorf("CryptoVerify failed: signature should be valid")
	}

	// Tamper with the message
	tampered := []byte("tampered message")
	valid = CryptoVerify(publicKey, tampered, signature)
	if valid {
		t.Errorf("CryptoVerify failed: signature should be invalid for tampered message")
	}

	// Tamper with the signature
	badSig := &sig{
		r: signature.R(),
		s: append(signature.S(), 0x00),
	}
	valid = CryptoVerify(publicKey, message, badSig)
	if valid {
		t.Errorf("CryptoVerify failed: signature should be invalid for tampered signature")
	}
}
