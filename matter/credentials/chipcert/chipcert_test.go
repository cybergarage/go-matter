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

package chipcert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func generateTestRoot(t *testing.T) ([]byte, *ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Second)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "go-matter Test Root CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(100 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{1, 2, 3, 4},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return der, key, cert
}

func generateTestNOC(t *testing.T, root *x509.Certificate, rootKey *ecdsa.PrivateKey, nodeIDHex, fabricIDHex string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Second)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			ExtraNames: []pkix.AttributeTypeAndValue{
				{Type: oidMatterNodeID, Value: nodeIDHex},
				{Type: oidMatterFabricID, Value: fabricIDHex},
			},
		},
		NotBefore:   now.Add(-time.Hour),
		NotAfter:    now.Add(100 * 365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root, &key.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestDERToTLVToDERRoot(t *testing.T) {
	rootDER, _, _ := generateTestRoot(t)

	tlvBytes, err := DERToTLV(rootDER)
	if err != nil {
		t.Fatalf("DERToTLV: %v", err)
	}
	roundTripDER, err := TLVToDER(tlvBytes)
	if err != nil {
		t.Fatalf("TLVToDER: %v", err)
	}

	orig, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	got, err := x509.ParseCertificate(roundTripDER)
	if err != nil {
		t.Fatalf("parse round-tripped certificate: %v", err)
	}

	if orig.Subject.CommonName != got.Subject.CommonName {
		t.Errorf("CommonName: got %q, want %q", got.Subject.CommonName, orig.Subject.CommonName)
	}
	if orig.SerialNumber.Cmp(got.SerialNumber) != 0 {
		t.Errorf("SerialNumber: got %v, want %v", got.SerialNumber, orig.SerialNumber)
	}
	if !got.IsCA {
		t.Errorf("IsCA: got false, want true")
	}
	if got.KeyUsage != orig.KeyUsage {
		t.Errorf("KeyUsage: got %v, want %v", got.KeyUsage, orig.KeyUsage)
	}
	if orig.NotBefore.Unix() != got.NotBefore.Unix() {
		t.Errorf("NotBefore: got %v, want %v", got.NotBefore, orig.NotBefore)
	}
	if orig.NotAfter.Unix() != got.NotAfter.Unix() {
		t.Errorf("NotAfter: got %v, want %v", got.NotAfter, orig.NotAfter)
	}

	// The round-tripped certificate must still verify against its own
	// (self-signed) signature, proving the reconstructed TBSCertificate DER
	// is byte-identical to what was originally signed.
	pool := x509.NewCertPool()
	pool.AddCert(got)
	if _, err := got.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Errorf("round-tripped root certificate failed self-verification: %v", err)
	}
}

func TestDERToTLVToDERNOC(t *testing.T) {
	rootDER, rootKey, root := generateTestRoot(t)
	nocDER := generateTestNOC(t, root, rootKey, "0000000000000042", "0000000000000099")

	tlvBytes, err := DERToTLV(nocDER)
	if err != nil {
		t.Fatalf("DERToTLV: %v", err)
	}
	roundTripDER, err := TLVToDER(tlvBytes)
	if err != nil {
		t.Fatalf("TLVToDER: %v", err)
	}

	got, err := x509.ParseCertificate(roundTripDER)
	if err != nil {
		t.Fatalf("parse round-tripped certificate: %v", err)
	}

	var nodeIDFound, fabricIDFound bool
	for _, atv := range got.Subject.Names {
		if atv.Type.Equal(oidMatterNodeID) {
			if atv.Value != "0000000000000042" {
				t.Errorf("NodeID RDN: got %v, want 0000000000000042", atv.Value)
			}
			nodeIDFound = true
		}
		if atv.Type.Equal(oidMatterFabricID) {
			if atv.Value != "0000000000000099" {
				t.Errorf("FabricID RDN: got %v, want 0000000000000099", atv.Value)
			}
			fabricIDFound = true
		}
	}
	if !nodeIDFound {
		t.Error("round-tripped NOC is missing the Matter NodeID RDN")
	}
	if !fabricIDFound {
		t.Error("round-tripped NOC is missing the Matter FabricID RDN")
	}
	if got.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("KeyUsage: got %v, want %v", got.KeyUsage, x509.KeyUsageDigitalSignature)
	}
	if len(got.ExtKeyUsage) != 2 {
		t.Errorf("ExtKeyUsage: got %v, want 2 entries", got.ExtKeyUsage)
	}

	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(rootCert)
	if _, err := got.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Errorf("round-tripped NOC failed chain verification against its root: %v", err)
	}
}

func TestTLVToDERRejectsEmpty(t *testing.T) {
	if _, err := TLVToDER(nil); err == nil {
		t.Error("expected error for empty TLV input")
	}
}

func TestDERToTLVRejectsGarbage(t *testing.T) {
	if _, err := DERToTLV([]byte{0x00, 0x01, 0x02}); err == nil {
		t.Error("expected error for invalid DER input")
	}
}
