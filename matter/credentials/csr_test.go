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

func encodeNOCSRElements(t *testing.T, csrDER, csrNonce []byte) []byte {
	t.Helper()
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	if err := enc.PutOctet(tlv.NewContextTag(tagCSR), csrDER); err != nil {
		t.Fatal(err)
	}
	if err := enc.PutOctet(tlv.NewContextTag(tagCSRNonce), csrNonce); err != nil {
		t.Fatal(err)
	}
	if err := enc.EndContainer(); err != nil {
		t.Fatal(err)
	}
	return enc.Bytes()
}

func TestParseNOCSRElements(t *testing.T) {
	csr := generateTestCSR(t)
	nonce := bytes.Repeat([]byte{0x42}, csrNonceLength)
	tlvBytes := encodeNOCSRElements(t, csr.Raw, nonce)

	got, err := ParseNOCSRElements(tlvBytes)
	if err != nil {
		t.Fatalf("ParseNOCSRElements() error = %v", err)
	}
	if !bytes.Equal(got.CSR, csr.Raw) {
		t.Error("CSR mismatch")
	}
	if !bytes.Equal(got.CSRNonce, nonce) {
		t.Error("CSRNonce mismatch")
	}

	parsedCSR, err := ParseCSR(got.CSR)
	if err != nil {
		t.Fatalf("ParseCSR() error = %v", err)
	}
	if !parsedCSR.PublicKey.(*ecdsa.PublicKey).Equal(csr.PublicKey.(*ecdsa.PublicKey)) {
		t.Error("parsed CSR public key mismatch")
	}
}

func TestParseNOCSRElementsRejectsMissingFields(t *testing.T) {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	if err := enc.EndContainer(); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseNOCSRElements(enc.Bytes()); err == nil {
		t.Error("expected error for missing fields")
	}
}

func TestVerifyNOCSRElementsSignature(t *testing.T) {
	dacKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr := generateTestCSR(t)
	nonce := bytes.Repeat([]byte{0x11}, csrNonceLength)
	nocsrElementsTLV := encodeNOCSRElements(t, csr.Raw, nonce)
	challenge := bytes.Repeat([]byte{0x22}, 16)

	msg := append(append([]byte{}, nocsrElementsTLV...), challenge...)
	sig, err := mcrypto.CryptoSign(mcrypto.NewPrivateKey(dacKey), msg)
	if err != nil {
		t.Fatal(err)
	}
	sigBytes := make([]byte, 64)
	copy(sigBytes[32-len(sig.R()):32], sig.R())
	copy(sigBytes[64-len(sig.S()):64], sig.S())

	if err := VerifyNOCSRElementsSignature(nocsrElementsTLV, challenge, sigBytes, &dacKey.PublicKey); err != nil {
		t.Errorf("VerifyNOCSRElementsSignature() error = %v, want nil", err)
	}

	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyNOCSRElementsSignature(nocsrElementsTLV, challenge, sigBytes, &otherKey.PublicKey); err == nil {
		t.Error("expected error verifying against the wrong public key")
	}
}
