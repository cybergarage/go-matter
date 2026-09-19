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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/cybergarage/go-matter/matter/cluster/operationalcredentials"
	"github.com/cybergarage/go-matter/matter/credentials"
)

var oidTestRootCommonName = asn1.ObjectIdentifier{2, 5, 4, 3}

// utf8CommonName builds a CommonName RDN explicitly tagged as ASN.1
// UTF8String, rather than using pkix.Name's CommonName convenience field
// (which Go's ASN.1 marshaler encodes as PrintableString for content that
// fits that narrower charset, as "mockdevice test root" does).
// connectedhomeip's own certificate reconstruction
// (src/credentials/CHIPCert.cpp ChipDN::EncodeToASN1) always emits
// UTF8String for CommonName, and this repo's own chipcert TLV encoder
// matches that (chipcert.go's encodeRDN) — a cert signed with
// PrintableString CommonName reproduces different TBS bytes than what
// chipcert.TLVToDER reconstructs, invalidating its own self-signature after
// the round trip a real device (and this test, via AddTrustedRootCertificate)
// performs. Reproduced directly by this test before this fix.
func utf8CommonName(s string) pkix.AttributeTypeAndValue {
	return pkix.AttributeTypeAndValue{
		Type:  oidTestRootCommonName,
		Value: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagUTF8String, Bytes: []byte(s)},
	}
}

// generateTestRootCA builds a self-signed ECDSA P-256 root certificate/key
// suitable for chipcert.DERToTLV/TLVToDER's round trip and
// credentials.NewCertificateAuthority. SubjectKeyId/AuthorityKeyId are set
// explicitly (RFC 5280 §4.2.1.2 method 1: SHA-1 of the subjectPublicKey BIT
// STRING content) — the same requirement matter/credentials/ca.go's IssueNOC
// and mattertest/certs/certgen.go document: connectedhomeip's
// ChipCertificateSet::LoadCert rejects any certificate lacking them, and a
// root missing its own AuthorityKeyId (self-referential for a self-signed
// root) reconstructs different TBS bytes on the way back through
// chipcert.TLVToDER than what was actually signed, breaking its own
// self-signature — reproduced directly by this test before this fix.
func generateTestRootCA(t *testing.T) ([]byte, []byte, *ecdsa.PrivateKey) {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate root key: %v", err)
	}
	pubKeyBytes := elliptic.Marshal(rootKey.PublicKey.Curve, rootKey.PublicKey.X, rootKey.PublicKey.Y)
	skid := sha1.Sum(pubKeyBytes) //nolint:gosec // RFC 5280 SubjectKeyId method 1 mandates SHA-1.
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			ExtraNames: []pkix.AttributeTypeAndValue{utf8CommonName("mockdevice test root")},
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          skid[:],
		AuthorityKeyId:        skid[:],
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create root certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(rootKey)
	if err != nil {
		t.Fatalf("marshal root key: %v", err)
	}
	return der, keyDER, rootKey
}

func TestOperationalCredentialsHandlers(t *testing.T) {
	clientSess, deviceSess := newFabricatedSessionPair(t)

	attestation, err := generateAttestationIdentity()
	if err != nil {
		t.Fatalf("generateAttestationIdentity() error = %v", err)
	}
	fs := newFabricState(attestation)

	srv := newIMServer(deviceSess)
	registerOperationalCredentialsHandlers(srv, fs, deviceSess.SessionKeys().AttestationChallenge, nil)
	serveContinuously(t, srv)

	challenge := clientSess.SessionKeys().AttestationChallenge()

	// AttestationRequest
	attNonce := bytesOf(0xA1, 32)
	elements, sig, err := operationalcredentials.AttestationRequest(clientSess, defaultEndpointID, attNonce)
	if err != nil {
		t.Fatalf("AttestationRequest() error = %v", err)
	}
	if err := credentials.VerifyAttestationSignature(elements, challenge, sig, &attestation.dacPriv.PublicKey); err != nil {
		t.Fatalf("VerifyAttestationSignature() error = %v", err)
	}
	parsedAttestation, err := credentials.ParseAttestationElements(elements)
	if err != nil {
		t.Fatalf("ParseAttestationElements() error = %v", err)
	}
	if !bytes.Equal(parsedAttestation.Nonce, attNonce) {
		t.Errorf("AttestationElements.Nonce = %x, want %x", parsedAttestation.Nonce, attNonce)
	}

	// CertificateChainRequest(DAC) / CertificateChainRequest(PAI)
	dacDER, err := operationalcredentials.CertificateChainRequest(clientSess, defaultEndpointID, 1)
	if err != nil {
		t.Fatalf("CertificateChainRequest(DAC) error = %v", err)
	}
	if !bytes.Equal(dacDER, attestation.dacCertDER) {
		t.Error("CertificateChainRequest(DAC) returned a different certificate than generateAttestationIdentity produced")
	}
	paiDER, err := operationalcredentials.CertificateChainRequest(clientSess, defaultEndpointID, 2)
	if err != nil {
		t.Fatalf("CertificateChainRequest(PAI) error = %v", err)
	}
	if !bytes.Equal(paiDER, attestation.paiCertDER) {
		t.Error("CertificateChainRequest(PAI) returned a different certificate than generateAttestationIdentity produced")
	}

	// CSRRequest
	csrNonce := bytesOf(0xC5, 32)
	csrElements, csrSig, err := operationalcredentials.CSRRequest(clientSess, defaultEndpointID, csrNonce)
	if err != nil {
		t.Fatalf("CSRRequest() error = %v", err)
	}
	if err := credentials.VerifyNOCSRElementsSignature(csrElements, challenge, csrSig, &attestation.dacPriv.PublicKey); err != nil {
		t.Fatalf("VerifyNOCSRElementsSignature() error = %v", err)
	}
	nocsr, err := credentials.ParseNOCSRElements(csrElements)
	if err != nil {
		t.Fatalf("ParseNOCSRElements() error = %v", err)
	}
	if !bytes.Equal(nocsr.CSRNonce, csrNonce) {
		t.Errorf("NOCSRElements.CSRNonce = %x, want %x", nocsr.CSRNonce, csrNonce)
	}
	csr, err := credentials.ParseCSR(nocsr.CSR)
	if err != nil {
		t.Fatalf("ParseCSR() error = %v", err)
	}
	csrPub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || !csrPub.Equal(&fs.nocKey.PublicKey) {
		t.Error("parsed CSR public key does not match the mock device's own generated NOC key")
	}

	// Issue the NOC from the CSR, exactly as matter/commissioning_impl.go does.
	rootDER, rootKeyDER, rootKey := generateTestRootCA(t)
	const fabricID = 0x2222222222222222
	const nodeID = 0x1111111111111111
	ca, err := credentials.NewCertificateAuthority(rootDER, rootKeyDER, fabricID)
	if err != nil {
		t.Fatalf("NewCertificateAuthority() error = %v", err)
	}
	nocDER, err := ca.IssueNOC(csr, nodeID)
	if err != nil {
		t.Fatalf("IssueNOC() error = %v", err)
	}

	// AddTrustedRootCertificate / AddNOC
	if err := operationalcredentials.AddTrustedRootCertificate(clientSess, defaultEndpointID, ca.RootCertificateDER()); err != nil {
		t.Fatalf("AddTrustedRootCertificate() error = %v", err)
	}
	ipk := bytesOf(0x1A, 16)
	const caseAdminSubject = 0x0000000000000001
	const adminVendorID = 0xFFF1
	if err := operationalcredentials.AddNOC(clientSess, defaultEndpointID, nocDER, nil, ipk, caseAdminSubject, adminVendorID); err != nil {
		t.Fatalf("AddNOC() error = %v", err)
	}

	if fs.nodeID != nodeID {
		t.Errorf("fabricState.nodeID = 0x%016X, want 0x%016X", fs.nodeID, uint64(nodeID))
	}
	if fs.fabricID != fabricID {
		t.Errorf("fabricState.fabricID = 0x%016X, want 0x%016X", fs.fabricID, uint64(fabricID))
	}
	if !bytes.Equal(fs.rawIPK, ipk) {
		t.Errorf("fabricState.rawIPK = %x, want %x", fs.rawIPK, ipk)
	}
	if fs.caseAdminSubject != caseAdminSubject {
		t.Errorf("fabricState.caseAdminSubject = 0x%016X, want 0x%016X", fs.caseAdminSubject, uint64(caseAdminSubject))
	}
	if fs.adminVendorID != adminVendorID {
		t.Errorf("fabricState.adminVendorID = 0x%04X, want 0x%04X", fs.adminVendorID, uint16(adminVendorID))
	}
	// fs.rootCertDER went through chipcert.DERToTLV/TLVToDER (the same
	// round trip a real device performs), which is not required to
	// reproduce byte-identical DER — only a semantically equivalent
	// certificate (same subject public key, still verifies its own
	// self-signature).
	roundTrippedRoot, err := x509.ParseCertificate(fs.rootCertDER)
	if err != nil {
		t.Fatalf("parse round-tripped root certificate: %v", err)
	}
	if err := roundTrippedRoot.CheckSignatureFrom(roundTrippedRoot); err != nil {
		t.Errorf("round-tripped root certificate self-signature invalid: %v", err)
	}
	roundTrippedPub, ok := roundTrippedRoot.PublicKey.(*ecdsa.PublicKey)
	if !ok || !roundTrippedPub.Equal(&rootKey.PublicKey) {
		t.Error("round-tripped root certificate's public key does not match the original root key")
	}
}
