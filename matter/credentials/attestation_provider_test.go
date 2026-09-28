// Copyright (C) 2026 The go-matter Authors. All rights reserved.
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

package credentials

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestSoftwareSigner(t *testing.T) {
	s, err := GenerateSoftwareSigner()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("message")
	sig, err := s.Sign(msg)
	if err != nil || len(sig) != rawSignatureLen {
		t.Fatalf("Sign() = (%d bytes, %v)", len(sig), err)
	}
	if err := VerifySignature(s.PublicKey(), msg, sig); err != nil {
		t.Fatalf("VerifySignature() = %v", err)
	}
	if err := VerifySignature(s.PublicKey(), []byte("other"), sig); err == nil {
		t.Fatal("a signature verified for another message")
	}

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(priv)
	parsed, err := ParseSoftwareSigner(der)
	if err != nil || !parsed.PublicKey().Equal(&priv.PublicKey) {
		t.Fatalf("ParseSoftwareSigner(SEC 1) = (%v, %v)", parsed, err)
	}
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(priv)
	if parsed, err := ParseSoftwareSigner(pkcs8); err != nil || !parsed.PublicKey().Equal(&priv.PublicKey) {
		t.Fatalf("ParseSoftwareSigner(PKCS #8) = (%v, %v)", parsed, err)
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, err := NewSoftwareSigner(p384); err == nil {
		t.Fatal("NewSoftwareSigner accepted a P-384 key")
	}
}

func TestCreateCSR(t *testing.T) {
	s, _ := GenerateSoftwareSigner()
	der, err := CreateCSR(s)
	if err != nil {
		t.Fatal(err)
	}
	// The commissioner's own parser checks the CSR's signature.
	csr, err := ParseCSR(der)
	if err != nil {
		t.Fatalf("ParseCSR() = %v", err)
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(s.PublicKey()) {
		t.Fatal("the CSR does not carry the signer's public key")
	}
}

// selfSignedDAC returns a certificate for signer's key, standing in for a
// DAC.
func selfSignedDAC(t *testing.T, signer Signer) []byte {
	t.Helper()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "DAC"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, signer.PublicKey(), priv)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestAttestationElementsRoundTrip(t *testing.T) {
	signer, _ := GenerateSoftwareSigner()
	dac := selfSignedDAC(t, signer)
	p, err := NewAttestationProvider(dac, dac, []byte("cd"), nil, signer)
	if err != nil {
		t.Fatal(err)
	}

	nonce := bytes.Repeat([]byte{7}, 32)
	elements, err := BuildAttestationElements(p.CertificationDeclaration(), nonce, 0, []byte("fw"))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseAttestationElements(elements)
	if err != nil {
		t.Fatalf("ParseAttestationElements() = %v", err)
	}
	if !bytes.Equal(parsed.CertificationDeclaration, []byte("cd")) || !bytes.Equal(parsed.Nonce, nonce) || !bytes.Equal(parsed.FirmwareInfo, []byte("fw")) {
		t.Fatalf("parsed %+v", parsed)
	}

	challenge := bytes.Repeat([]byte{9}, 16)
	sig, err := SignWithChallenge(p.SignWithDAC, elements, challenge)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyAttestationSignature(elements, challenge, sig, signer.PublicKey()); err != nil {
		t.Fatalf("VerifyAttestationSignature() = %v", err)
	}

	if _, err := BuildAttestationElements(nil, nonce[:31], 0, nil); err == nil {
		t.Fatal("BuildAttestationElements accepted a 31-byte nonce")
	}

	other, _ := GenerateSoftwareSigner()
	if _, err := NewAttestationProvider(dac, dac, []byte("cd"), nil, other); err == nil {
		t.Fatal("NewAttestationProvider accepted a signer without the DAC's key")
	}
}

func TestNOCSRElementsRoundTrip(t *testing.T) {
	dacSigner, _ := GenerateSoftwareSigner()
	opSigner, _ := GenerateSoftwareSigner()
	csr, err := CreateCSR(opSigner)
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{3}, 32)
	elements, err := BuildNOCSRElements(csr, nonce)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseNOCSRElements(elements)
	if err != nil || !bytes.Equal(parsed.CSR, csr) || !bytes.Equal(parsed.CSRNonce, nonce) {
		t.Fatalf("ParseNOCSRElements() = (%+v, %v)", parsed, err)
	}
	challenge := bytes.Repeat([]byte{1}, 16)
	sig, _ := SignWithChallenge(dacSigner.Sign, elements, challenge)
	if err := VerifyNOCSRElementsSignature(elements, challenge, sig, dacSigner.PublicKey()); err != nil {
		t.Fatalf("VerifyNOCSRElementsSignature() = %v", err)
	}
}
