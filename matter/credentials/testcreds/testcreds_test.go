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

package testcreds

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"testing"

	"github.com/cybergarage/go-matter/matter/credentials"
)

// TestChainOfTrust checks that the bundled credentials are what a
// commissioner expects: DAC -> PAI -> PAA verifies, the DAC names the
// vendor and product, and the provider signs with the DAC's key.
func TestChainOfTrust(t *testing.T) {
	p, err := AttestationProvider()
	if err != nil {
		t.Fatal(err)
	}
	dac, err := x509.ParseCertificate(p.DAC())
	if err != nil {
		t.Fatal(err)
	}
	pai, _ := x509.ParseCertificate(p.PAI())
	paa, _ := x509.ParseCertificate(PAA())

	roots := x509.NewCertPool()
	roots.AddCert(paa)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(pai)
	if _, err := dac.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Fatalf("DAC -> PAI -> PAA does not verify: %v", err)
	}
	if !bytes.Contains(dac.RawSubject, []byte("FFF1")) || !bytes.Contains(dac.RawSubject, []byte("8000")) {
		t.Fatalf("DAC subject %s does not name vendor FFF1 and product 8000", dac.Subject)
	}

	msg := []byte("attestation elements || challenge")
	sig, err := p.SignWithDAC(msg)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := dac.PublicKey.(*ecdsa.PublicKey)
	if err := credentials.VerifySignature(pub, msg, sig); err != nil {
		t.Fatalf("the DAC's public key does not verify the provider's signature: %v", err)
	}
	if len(p.CertificationDeclaration()) == 0 {
		t.Fatal("no Certification Declaration")
	}
	if _, err := x509.ParseCertificate(CDSigningCertificate()); err != nil {
		t.Fatal(err)
	}
}
