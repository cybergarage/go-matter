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

package caseprotocol

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"
)

// TestSignWithKeyAndVerifySignatureFromCertRoundTrip guards against a
// regression where signWithKey/verifySignatureFromCert silently failed for
// any real (non-package-internal) ECDSA key: matter/crypto's ECDSASign and
// ECDSAVerify type-assert their PublicKey/PrivateKey arguments down to that
// package's own concrete types, so wrapping a *ecdsa.PrivateKey/PublicKey in
// a locally defined adapter type (as this file previously did) always failed
// the assertion — signWithKey returned "invalid: private key" and
// verifySignatureFromCert always returned false, which would have made
// CASE's Sigma3 signing and Sigma2 signature verification fail against any
// real device.
func TestSignWithKeyAndVerifySignatureFromCertRoundTrip(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("sigma-tbs-data")

	sigBytes, err := signWithKey(priv, msg)
	if err != nil {
		t.Fatalf("signWithKey() error = %v", err)
	}
	if len(sigBytes) != signatureLen {
		t.Fatalf("signWithKey() signature length = %d, want %d", len(sigBytes), signatureLen)
	}

	cert := &x509.Certificate{PublicKey: &priv.PublicKey}
	if !verifySignatureFromCert(cert, msg, sigBytes) {
		t.Fatal("verifySignatureFromCert() = false, want true for a matching signature")
	}
	if verifySignatureFromCert(cert, []byte("tampered"), sigBytes) {
		t.Fatal("verifySignatureFromCert() = true for a mismatched message, want false")
	}
}
