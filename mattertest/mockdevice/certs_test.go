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

package mockdevice

import (
	"crypto/ecdsa"
	"crypto/x509"
	"testing"
)

func TestGenerateAttestationIdentity(t *testing.T) {
	id, err := generateAttestationIdentity()
	if err != nil {
		t.Fatalf("generateAttestationIdentity() error = %v", err)
	}
	if id.dacPriv == nil {
		t.Fatal("dacPriv is nil")
	}

	dacCert, err := x509.ParseCertificate(id.dacCertDER)
	if err != nil {
		t.Fatalf("parse DAC certificate: %v", err)
	}
	dacPub, ok := dacCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("DAC certificate public key type = %T, want *ecdsa.PublicKey", dacCert.PublicKey)
	}
	if !dacPub.Equal(id.dacPriv.Public()) {
		t.Error("DAC certificate public key does not match dacPriv")
	}
	if err := dacCert.CheckSignature(dacCert.SignatureAlgorithm, dacCert.RawTBSCertificate, dacCert.Signature); err != nil {
		t.Errorf("DAC certificate is not self-signed correctly: %v", err)
	}

	paiCert, err := x509.ParseCertificate(id.paiCertDER)
	if err != nil {
		t.Fatalf("parse PAI certificate: %v", err)
	}
	if err := paiCert.CheckSignature(paiCert.SignatureAlgorithm, paiCert.RawTBSCertificate, paiCert.Signature); err != nil {
		t.Errorf("PAI certificate is not self-signed correctly: %v", err)
	}
	if !paiCert.IsCA {
		t.Error("PAI certificate should be marked as CA")
	}

	// Two calls must produce distinct identities (fresh keys each time).
	id2, err := generateAttestationIdentity()
	if err != nil {
		t.Fatalf("generateAttestationIdentity() (second call) error = %v", err)
	}
	if string(id.dacCertDER) == string(id2.dacCertDER) {
		t.Error("two calls to generateAttestationIdentity produced identical DAC certificates")
	}
}
