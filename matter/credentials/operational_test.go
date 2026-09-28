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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/cybergarage/go-matter/matter/credentials/chipcert"
)

// newTestRoot returns a Matter RCAC, DER-encoded, and its key.
func newTestRoot(t *testing.T, rcacID string) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := key.PublicKey.ECDH()
	if err != nil {
		t.Fatal(err)
	}
	skid := sha1.Sum(pub.Bytes())
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{ExtraNames: []pkix.AttributeTypeAndValue{utf8Attr(oidMatterRCACID, rcacID)}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          skid[:],
		AuthorityKeyId:        skid[:],
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der, key
}

// issueTestNOC has a CA on root issue a NOC for signer's key, and returns
// the root and the NOC in the Matter TLV encoding.
func issueTestNOC(t *testing.T, rootDER []byte, rootKey *ecdsa.PrivateKey, signer Signer, fabricID, nodeID uint64) ([]byte, []byte) {
	t.Helper()
	keyDER, err := x509.MarshalPKCS8PrivateKey(rootKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := NewCertificateAuthority(rootDER, keyDER, fabricID)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := CreateCSR(signer)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := ParseCSR(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	nocDER, err := ca.IssueNOC(csr, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	rootTLV, err := chipcert.DERToTLV(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	nocTLV, err := chipcert.DERToTLV(nocDER)
	if err != nil {
		t.Fatal(err)
	}
	return rootTLV, nocTLV
}

func TestVerifyOperationalChain(t *testing.T) {
	const fabricID, nodeID = 0x2906C908D115D362, 0x0000000012344321
	rootDER, rootKey := newTestRoot(t, "0000000000000001")
	signer, err := GenerateSoftwareSigner()
	if err != nil {
		t.Fatal(err)
	}
	rootTLV, nocTLV := issueTestNOC(t, rootDER, rootKey, signer, fabricID, nodeID)

	rcac, err := ParseOperationalCertificate(rootTLV)
	if err != nil {
		t.Fatal(err)
	}
	noc, err := ParseOperationalCertificate(nocTLV)
	if err != nil {
		t.Fatal(err)
	}
	if noc.NodeID != nodeID || noc.FabricID != fabricID {
		t.Fatalf("NOC node ID 0x%X fabric ID 0x%X, want 0x%X and 0x%X", noc.NodeID, noc.FabricID, nodeID, fabricID)
	}
	signerPub, _ := signer.PublicKey().ECDH()
	if string(noc.PublicKey) != string(signerPub.Bytes()) {
		t.Fatal("the NOC's public key is not the CSR's")
	}
	if rcac.NodeID != 0 || rcac.FabricID != 0 {
		t.Fatalf("root node ID 0x%X fabric ID 0x%X, want none", rcac.NodeID, rcac.FabricID)
	}
	if err := VerifyOperationalChain(noc, nil, rcac); err != nil {
		t.Fatalf("VerifyOperationalChain() error = %v", err)
	}

	// A NOC does not chain to another root, and is not a root itself.
	otherDER, _ := newTestRoot(t, "0000000000000002")
	otherTLV, err := chipcert.DERToTLV(otherDER)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ParseOperationalCertificate(otherTLV)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyOperationalChain(noc, nil, other); !errors.Is(err, ErrInvalidOperationalCertificate) {
		t.Fatalf("VerifyOperationalChain(other root) error = %v", err)
	}
	if err := VerifyRootCertificate(noc); !errors.Is(err, ErrInvalidOperationalCertificate) {
		t.Fatalf("VerifyRootCertificate(NOC) error = %v", err)
	}
	if _, err := ParseOperationalCertificate([]byte{0x15, 0x18}); !errors.Is(err, ErrInvalidOperationalCertificate) {
		t.Fatalf("ParseOperationalCertificate(garbage) error = %v", err)
	}
}

func TestOperationalIdentifierRanges(t *testing.T) {
	for _, tc := range []struct {
		id          uint64
		operational bool
		cat         bool
	}{
		{0, false, false},
		{1, true, false},
		{0xFFFF_FFEF_FFFF_FFFF, true, false},
		{0xFFFF_FFF0_0000_0000, false, false},
		{0xFFFF_FFFD_0001_0001, false, true},
		{0xFFFF_FFFD_0001_0000, false, false},
	} {
		if got := IsOperationalNodeID(tc.id); got != tc.operational {
			t.Errorf("IsOperationalNodeID(0x%X) = %v", tc.id, got)
		}
		if got := IsCASEAuthenticatedTag(tc.id); got != tc.cat {
			t.Errorf("IsCASEAuthenticatedTag(0x%X) = %v", tc.id, got)
		}
	}
}
