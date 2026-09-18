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
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func generateTestCA(t *testing.T) (*CertificateAuthority, *x509.Certificate) {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(100 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	rootKeyDER, err := x509.MarshalECPrivateKey(rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: rootKeyDER})

	ca, err := NewCertificateAuthority(rootDER, rootKeyPEM, 0x2)
	if err != nil {
		t.Fatal(err)
	}
	return ca, rootCert
}

func generateTestCSR(t *testing.T) *x509.CertificateRequest {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.CertificateRequest{}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

func TestCertificateAuthorityIssueNOC(t *testing.T) {
	ca, rootCert := generateTestCA(t)
	csr := generateTestCSR(t)

	nocDER, err := ca.IssueNOC(csr, 0x42)
	if err != nil {
		t.Fatalf("IssueNOC() error = %v", err)
	}
	nocCert, err := x509.ParseCertificate(nocDER)
	if err != nil {
		t.Fatalf("parse issued NOC: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(rootCert)
	if _, err := nocCert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Errorf("issued NOC does not verify against CA root: %v", err)
	}

	var foundNodeID, foundFabricID bool
	for _, atv := range nocCert.Subject.Names {
		if atv.Type.Equal(oidMatterNodeID) {
			if atv.Value != uint64ToHexRDNValue(0x42) {
				t.Errorf("NodeID RDN = %v, want %v", atv.Value, uint64ToHexRDNValue(0x42))
			}
			foundNodeID = true
		}
		if atv.Type.Equal(oidMatterFabricID) {
			if atv.Value != uint64ToHexRDNValue(0x2) {
				t.Errorf("FabricID RDN = %v, want %v", atv.Value, uint64ToHexRDNValue(0x2))
			}
			foundFabricID = true
		}
	}
	if !foundNodeID {
		t.Error("issued NOC missing Matter NodeID RDN")
	}
	if !foundFabricID {
		t.Error("issued NOC missing Matter FabricID RDN")
	}

	if !nocCert.PublicKey.(*ecdsa.PublicKey).Equal(csr.PublicKey.(*ecdsa.PublicKey)) {
		t.Error("issued NOC public key does not match CSR public key")
	}

	// connectedhomeip's ChipCertificateSet::LoadCert (src/credentials/CHIPCert.cpp)
	// rejects ANY certificate loaded for chain validation — including a
	// non-CA leaf NOC — that lacks a SubjectKeyId extension, with
	// CHIP_ERROR_UNSUPPORTED_CERT_FORMAT, which the AddNOC handler surfaces
	// to the commissioner as NOCResponse status=3 (InvalidNOC). A real
	// device rejected AddNOC for exactly this reason.
	if len(nocCert.SubjectKeyId) == 0 {
		t.Error("issued NOC is missing a SubjectKeyId extension")
	}
	csrPub := csr.PublicKey.(*ecdsa.PublicKey)
	wantSKID := sha1.Sum(elliptic.Marshal(csrPub.Curve, csrPub.X, csrPub.Y))
	if !bytes.Equal(nocCert.SubjectKeyId, wantSKID[:]) {
		t.Errorf("NOC SubjectKeyId = %x, want SHA-1(pubkey) = %x", nocCert.SubjectKeyId, wantSKID)
	}

	// connectedhomeip's own reference X.509 generator
	// (src/credentials/GenerateChipX509Cert.cpp EncodeNOCSpecificExtensions)
	// always emits a BasicConstraints extension for a NOC, even though its
	// content is empty for a non-CA cert. Go's x509.CreateCertificate omits
	// the extension entirely unless BasicConstraintsValid is set on the
	// template, which produced a NOC structurally unlike the reference's and
	// was rejected by a real device with NOCResponse status=3 (InvalidNOC).
	if !nocCert.BasicConstraintsValid {
		t.Error("issued NOC is missing a BasicConstraints extension")
	}
	if nocCert.IsCA {
		t.Error("issued NOC must not be a CA certificate")
	}
}

func TestNewCertificateAuthorityRejectsMismatchedKey(t *testing.T) {
	_, rootCert := generateTestCA(t)
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherKeyDER, err := x509.MarshalECPrivateKey(otherKey)
	if err != nil {
		t.Fatal(err)
	}
	otherKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: otherKeyDER})

	if _, err := NewCertificateAuthority(rootCert.Raw, otherKeyPEM, 0x2); err == nil {
		t.Error("expected error for mismatched root key")
	}
}

func TestNewCertificateAuthorityRejectsMissingFabricID(t *testing.T) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             now,
		NotAfter:              now.Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootKeyDER, err := x509.MarshalECPrivateKey(rootKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewCertificateAuthority(rootDER, rootKeyDER, 0); err == nil {
		t.Error("expected error for missing fabric ID")
	}
}
