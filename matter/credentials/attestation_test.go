// Copyright (C) 2026 The go-matter Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package credentials

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	mcrypto "github.com/cybergarage/go-matter/matter/crypto"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
)

func encodeAttestationElements(t *testing.T, cd, nonce []byte, timestamp uint32) []byte {
	t.Helper()
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	if err := enc.PutOctet(tlv.NewContextTag(tagCertificationDeclaration), cd); err != nil {
		t.Fatal(err)
	}
	if err := enc.PutOctet(tlv.NewContextTag(tagAttestationNonce), nonce); err != nil {
		t.Fatal(err)
	}
	enc.PutUnsigned4(tlv.NewContextTag(tagAttestationTimestamp), timestamp)
	if err := enc.EndContainer(); err != nil {
		t.Fatal(err)
	}
	return enc.Bytes()
}

func TestParseAttestationElements(t *testing.T) {
	cd := []byte{0xAA, 0xBB, 0xCC}
	nonce := bytes.Repeat([]byte{0x33}, attestationNonceLength)
	tlvBytes := encodeAttestationElements(t, cd, nonce, 12345)

	got, err := ParseAttestationElements(tlvBytes)
	if err != nil {
		t.Fatalf("ParseAttestationElements() error = %v", err)
	}
	if !bytes.Equal(got.CertificationDeclaration, cd) {
		t.Error("CertificationDeclaration mismatch")
	}
	if !bytes.Equal(got.Nonce, nonce) {
		t.Error("Nonce mismatch")
	}
	if got.Timestamp != 12345 {
		t.Errorf("Timestamp = %d, want 12345", got.Timestamp)
	}
}

func TestParseAttestationElementsRejectsMissingFields(t *testing.T) {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	if err := enc.EndContainer(); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseAttestationElements(enc.Bytes()); err == nil {
		t.Error("expected error for missing fields")
	}
}

func TestVerifyAttestationSignature(t *testing.T) {
	dacKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{0x44}, attestationNonceLength)
	attestationElementsTLV := encodeAttestationElements(t, []byte{0x01}, nonce, 999)
	challenge := bytes.Repeat([]byte{0x55}, 16)

	msg := append(append([]byte{}, attestationElementsTLV...), challenge...)
	sig, err := mcrypto.CryptoSign(mcrypto.NewPrivateKey(dacKey), msg)
	if err != nil {
		t.Fatal(err)
	}
	sigBytes := make([]byte, 64)
	copy(sigBytes[32-len(sig.R()):32], sig.R())
	copy(sigBytes[64-len(sig.S()):64], sig.S())

	if err := VerifyAttestationSignature(attestationElementsTLV, challenge, sigBytes, &dacKey.PublicKey); err != nil {
		t.Errorf("VerifyAttestationSignature() error = %v, want nil", err)
	}
	if err := VerifyAttestationSignature([]byte("tampered"), challenge, sigBytes, &dacKey.PublicKey); err == nil {
		t.Error("expected error for tampered AttestationElements")
	}
}
