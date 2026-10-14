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
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/cybergarage/go-matter/matter/encoding/tlv"
)

// attestationPKI is a self-issued attestation hierarchy: a PAA, a PAI and a
// DAC, and a key which signs Certification Declarations.
type attestationPKI struct {
	t        *testing.T
	paa, pai *x509.Certificate
	paaKey   *ecdsa.PrivateKey
	paiKey   *ecdsa.PrivateKey
	dac      *x509.Certificate
	dacKey   *ecdsa.PrivateKey
	cdSigner *x509.Certificate
	cdKey    *ecdsa.PrivateKey
}

type pkiIDs struct {
	paaVID     string // "" for none
	paiVID     string
	paiPID     string // "" for none
	dacVID     string
	dacPID     string
	dacExpired bool
}

var defaultPKIIDs = pkiIDs{paaVID: "", paiVID: "FFF2", paiPID: "", dacVID: "FFF2", dacPID: "8001", dacExpired: false}

func newAttestationPKI(t *testing.T, ids pkiIDs) *attestationPKI {
	t.Helper()
	p := &attestationPKI{t: t}
	p.paaKey = newTestKey(t)
	p.paa = p.issue("Test PAA", ids.paaVID, "", true, nil, nil, p.paaKey, false)
	p.paiKey = newTestKey(t)
	p.pai = p.issue("Test PAI", ids.paiVID, ids.paiPID, true, p.paa, p.paaKey, p.paiKey, false)
	p.dacKey = newTestKey(t)
	p.dac = p.issue("Test DAC", ids.dacVID, ids.dacPID, false, p.pai, p.paiKey, p.dacKey, ids.dacExpired)
	p.cdKey = newTestKey(t)
	p.cdSigner = p.issue("Test CD Signer", "", "", false, nil, nil, p.cdKey, false)
	return p
}

func newTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

var testSerial int64

// issue creates a certificate for key, signed by parentKey as parent, or
// self-signed when parent is nil.
func (p *attestationPKI) issue(cn, vid, pid string, isCA bool, parent *x509.Certificate, parentKey, key *ecdsa.PrivateKey, expired bool) *x509.Certificate {
	p.t.Helper()
	names := []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: cn}}
	if vid != "" {
		names = append(names, pkix.AttributeTypeAndValue{Type: oidMatterVendorID, Value: vid})
	}
	if pid != "" {
		names = append(names, pkix.AttributeTypeAndValue{Type: oidMatterProductID, Value: pid})
	}
	skid := sha256.Sum256(elliptic.MarshalCompressed(elliptic.P256(), key.X, key.Y))
	now := time.Now()
	testSerial++
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(testSerial),
		Subject:               pkix.Name{ExtraNames: names},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		SubjectKeyId:          skid[:20],
		KeyUsage:              x509.KeyUsageDigitalSignature,
	}
	if expired {
		tmpl.NotBefore = now.Add(-48 * time.Hour)
		tmpl.NotAfter = now.Add(-24 * time.Hour)
	}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		tmpl.MaxPathLen = 1
		if parent != nil {
			tmpl.MaxPathLen = 0
			tmpl.MaxPathLenZero = true
		}
	}
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		p.t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		p.t.Fatal(err)
	}
	return cert
}

func (p *attestationPKI) store() AttestationTrustStore {
	return NewAttestationTrustStore([]*x509.Certificate{p.paa}, []*x509.Certificate{p.cdSigner})
}

// testCD is the content of a Certification Declaration to encode.
type testCD struct {
	vid           uint16
	pids          []uint16
	certType      CertificationType
	origin        *[2]uint16
	authorizedPAA [][]byte
	// formatVersion, certificateID and omitDeviceType, when set, make a
	// malformed declaration.
	formatVersion  uint16
	certificateID  string
	omitDeviceType bool
}

func encodeTestCD(t *testing.T, cd testCD) []byte {
	t.Helper()
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	formatVersion := cd.formatVersion
	if formatVersion == 0 {
		formatVersion = 1
	}
	certificateID := cd.certificateID
	if certificateID == "" {
		certificateID = "ZIG20141ZB330001-24"
	}
	enc.PutUnsigned2(tlv.NewContextTag(tagCDFormatVersion), formatVersion)
	enc.PutUnsigned2(tlv.NewContextTag(tagCDVendorID), cd.vid)
	enc.BeginArray(tlv.NewContextTag(tagCDProductIDArray))
	for _, pid := range cd.pids {
		enc.PutUnsigned2(tlv.NewAnonymousTag(), pid)
	}
	mustEnd(t, enc)
	if !cd.omitDeviceType {
		enc.PutUnsigned4(tlv.NewContextTag(tagCDDeviceTypeID), 0x0100)
	}
	if err := enc.PutUTF8(tlv.NewContextTag(tagCDCertificateID), certificateID); err != nil {
		t.Fatal(err)
	}
	enc.PutUnsigned1(tlv.NewContextTag(tagCDSecurityLevel), 0)
	enc.PutUnsigned2(tlv.NewContextTag(tagCDSecurityInformation), 0)
	enc.PutUnsigned2(tlv.NewContextTag(tagCDVersionNumber), 1)
	enc.PutUnsigned1(tlv.NewContextTag(tagCDCertificationType), uint8(cd.certType))
	if cd.origin != nil {
		enc.PutUnsigned2(tlv.NewContextTag(tagCDDACOriginVendorID), cd.origin[0])
		enc.PutUnsigned2(tlv.NewContextTag(tagCDDACOriginProductID), cd.origin[1])
	}
	if len(cd.authorizedPAA) != 0 {
		enc.BeginArray(tlv.NewContextTag(tagCDAuthorizedPAAList))
		for _, id := range cd.authorizedPAA {
			if err := enc.PutOctet(tlv.NewAnonymousTag(), id); err != nil {
				t.Fatal(err)
			}
		}
		mustEnd(t, enc)
	}
	mustEnd(t, enc)
	return enc.Bytes()
}

func mustEnd(t *testing.T, enc tlv.Encoder) {
	t.Helper()
	if err := enc.EndContainer(); err != nil {
		t.Fatal(err)
	}
}

// signTestCD wraps content in CMS SignedData signed by key, identified by
// the subject key ID skid (6.3.2).
func signTestCD(t *testing.T, content []byte, skid []byte, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	digest := sha256.Sum256(content)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	digestAlgs, err := asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: oidDigestSHA256})
	if err != nil {
		t.Fatal(err)
	}
	sd := cmsSignedData{
		Version:          3,
		DigestAlgorithms: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: digestAlgs},
		EncapContentInfo: cmsEncapsulatedContentInfo{EContentType: oidCMSData, EContent: content},
		SignerInfos: []cmsSignerInfo{{
			Version:            3,
			SID:                asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: skid},
			DigestAlgorithm:    pkix.AlgorithmIdentifier{Algorithm: oidDigestSHA256},
			SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidSignatureECDSAWith},
			Signature:          sig,
		}},
	}
	sdDER, err := asn1.Marshal(sd)
	if err != nil {
		t.Fatal(err)
	}
	der, err := asn1.Marshal(cmsContentInfo{
		ContentType: oidCMSSignedData,
		Content:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: sdDER},
	})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// attestationCase builds the AttestationInfo a device of the PKI sends.
type attestationCase struct {
	pki       *attestationPKI
	cd        []byte
	nonce     []byte
	echoNonce []byte
	signer    *ecdsa.PrivateKey
	// vid and pid are the device's Basic Information; hasIDs is false when
	// they are unknown.
	vid, pid uint16
	hasIDs   bool
}

func newAttestationCase(t *testing.T, pki *attestationPKI, cd testCD) *attestationCase {
	t.Helper()
	if len(cd.pids) == 0 {
		cd = defaultTestCD
	}
	nonce := bytes.Repeat([]byte{0x42}, attestationNonceLength)
	return &attestationCase{
		pki:       pki,
		cd:        signTestCD(t, encodeTestCD(t, cd), pki.cdSigner.SubjectKeyId, pki.cdKey),
		nonce:     nonce,
		echoNonce: nonce,
		signer:    pki.dacKey,
		vid:       cd.vid,
		pid:       cd.pids[len(cd.pids)-1],
		hasIDs:    true,
	}
}

func (c *attestationCase) info(t *testing.T) AttestationInfo {
	t.Helper()
	challenge := bytes.Repeat([]byte{0x5A}, 16)
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	if err := enc.PutOctet(tlv.NewContextTag(tagCertificationDeclaration), c.cd); err != nil {
		t.Fatal(err)
	}
	if err := enc.PutOctet(tlv.NewContextTag(tagAttestationNonce), c.echoNonce); err != nil {
		t.Fatal(err)
	}
	enc.PutUnsigned4(tlv.NewContextTag(tagAttestationTimestamp), 0)
	mustEnd(t, enc)
	elements := enc.Bytes()
	msg := append(append([]byte{}, elements...), challenge...)
	digest := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, c.signer, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return AttestationInfo{
		DAC:                  c.pki.dac.Raw,
		PAI:                  c.pki.pai.Raw,
		AttestationElements:  elements,
		AttestationSignature: sig,
		AttestationChallenge: challenge,
		AttestationNonce:     c.nonce,
		VendorID:             c.vid,
		ProductID:            c.pid,
		HasBasicInformation:  c.hasIDs,
	}
}

var defaultTestCD = testCD{vid: 0xFFF2, pids: []uint16{0x8000, 0x8001}, certType: CertificationTypeDevelopmentAndTest}

type revokeAll struct{}

func (revokeAll) CheckRevocation(*x509.Certificate, *x509.Certificate) error {
	return errors.New("revoked")
}

func TestAttestationVerifier(t *testing.T) {
	type tc struct {
		name    string
		ids     pkiIDs
		cd      testCD
		mode    AttestationMode
		tweak   func(*attestationCase, *attestationPKI) AttestationTrustStore
		opts    []AttestationVerifierOption
		failure AttestationFailure // 0 for success
	}
	official := defaultTestCD
	official.certType = CertificationTypeOfficial
	prodIDs := pkiIDs{paiVID: "1234", dacVID: "1234", dacPID: "8001"}
	prodCD := testCD{vid: 0x1234, pids: []uint16{0x8001}, certType: CertificationTypeOfficial}

	tests := []tc{
		{name: "development accepts a trusted self-issued chain", ids: defaultPKIIDs, cd: defaultTestCD, mode: AttestationDevelopment},
		{name: "production accepts a certified product", ids: prodIDs, cd: prodCD, mode: AttestationProduction},
		{name: "production rejects a test vendor ID", ids: defaultPKIIDs, cd: official, mode: AttestationProduction, failure: AttestationFailureTestVendorID},
		{name: "production rejects a test declaration", ids: prodIDs, cd: testCD{vid: 0x1234, pids: []uint16{0x8001}}, mode: AttestationProduction, failure: AttestationFailureCDContent},
		{
			name: "none skips the chain", ids: defaultPKIIDs, cd: defaultTestCD, mode: AttestationNone,
			tweak: func(*attestationCase, *attestationPKI) AttestationTrustStore {
				return NewAttestationTrustStore(nil, nil)
			},
		},
		{
			name: "none still checks the signature", ids: defaultPKIIDs, cd: defaultTestCD, mode: AttestationNone,
			tweak: func(c *attestationCase, p *attestationPKI) AttestationTrustStore {
				c.signer = newTestKey(t)
				return p.store()
			},
			failure: AttestationFailureSignature,
		},
		{
			name: "nonce not echoed", ids: defaultPKIIDs, cd: defaultTestCD, mode: AttestationDevelopment,
			tweak: func(c *attestationCase, p *attestationPKI) AttestationTrustStore {
				c.echoNonce = bytes.Repeat([]byte{0x43}, attestationNonceLength)
				return p.store()
			},
			failure: AttestationFailureNonce,
		},
		{
			name: "PAA not trusted", ids: defaultPKIIDs, cd: defaultTestCD, mode: AttestationDevelopment,
			tweak: func(_ *attestationCase, p *attestationPKI) AttestationTrustStore {
				return NewAttestationTrustStore(nil, []*x509.Certificate{p.cdSigner})
			},
			failure: AttestationFailurePAANotFound,
		},
		{name: "expired DAC", ids: pkiIDs{paiVID: "FFF2", dacVID: "FFF2", dacPID: "8001", dacExpired: true}, cd: defaultTestCD, mode: AttestationDevelopment, failure: AttestationFailureChain},
		{name: "PAI and DAC vendor IDs differ", ids: pkiIDs{paiVID: "FFF3", dacVID: "FFF2", dacPID: "8001"}, cd: defaultTestCD, mode: AttestationDevelopment, failure: AttestationFailureVendorID},
		{name: "PAI and DAC product IDs differ", ids: pkiIDs{paiVID: "FFF2", paiPID: "8000", dacVID: "FFF2", dacPID: "8001"}, cd: defaultTestCD, mode: AttestationDevelopment, failure: AttestationFailureProductID},
		{name: "PAA and PAI vendor IDs differ", ids: pkiIDs{paaVID: "FFF3", paiVID: "FFF2", dacVID: "FFF2", dacPID: "8001"}, cd: defaultTestCD, mode: AttestationDevelopment, failure: AttestationFailureVendorID},
		{name: "DAC without product ID", ids: pkiIDs{paiVID: "FFF2", dacVID: "FFF2"}, cd: defaultTestCD, mode: AttestationDevelopment, failure: AttestationFailureMalformed},
		{
			name: "CD signer not trusted", ids: defaultPKIIDs, cd: defaultTestCD, mode: AttestationDevelopment,
			tweak: func(_ *attestationCase, p *attestationPKI) AttestationTrustStore {
				return NewAttestationTrustStore([]*x509.Certificate{p.paa}, nil)
			},
			failure: AttestationFailureCDSignerNotFound,
		},
		{
			name: "CD signed by another key", ids: defaultPKIIDs, cd: defaultTestCD, mode: AttestationDevelopment,
			tweak: func(c *attestationCase, p *attestationPKI) AttestationTrustStore {
				c.cd = signTestCD(t, encodeTestCD(t, defaultTestCD), p.cdSigner.SubjectKeyId, newTestKey(t))
				return p.store()
			},
			failure: AttestationFailureCDSignature,
		},
		{name: "CD for another vendor", ids: defaultPKIIDs, cd: testCD{vid: 0xFFF3, pids: []uint16{0x8001}}, mode: AttestationDevelopment, failure: AttestationFailureCDContent},
		{name: "CD without the product", ids: defaultPKIIDs, cd: testCD{vid: 0xFFF2, pids: []uint16{0x8000}}, mode: AttestationDevelopment, failure: AttestationFailureCDContent},
		{name: "CD with the DAC origin", ids: defaultPKIIDs, cd: testCD{vid: 0xFFF4, pids: []uint16{0x9000}, origin: &[2]uint16{0xFFF2, 0x8001}}, mode: AttestationDevelopment},
		{name: "CD with another DAC origin", ids: defaultPKIIDs, cd: testCD{vid: 0xFFF2, pids: []uint16{0x8001}, origin: &[2]uint16{0xFFF2, 0x8000}}, mode: AttestationDevelopment, failure: AttestationFailureCDContent},
		{
			name: "CD authorizes the PAA", ids: defaultPKIIDs, mode: AttestationDevelopment,
			tweak: func(c *attestationCase, p *attestationPKI) AttestationTrustStore {
				cd := defaultTestCD
				cd.authorizedPAA = [][]byte{p.paa.SubjectKeyId}
				c.cd = signTestCD(t, encodeTestCD(t, cd), p.cdSigner.SubjectKeyId, p.cdKey)
				return p.store()
			},
		},
		{
			name: "CD authorizes other PAAs", ids: defaultPKIIDs, mode: AttestationDevelopment,
			tweak: func(c *attestationCase, p *attestationPKI) AttestationTrustStore {
				cd := defaultTestCD
				cd.authorizedPAA = [][]byte{bytes.Repeat([]byte{0x01}, 20)}
				c.cd = signTestCD(t, encodeTestCD(t, cd), p.cdSigner.SubjectKeyId, p.cdKey)
				return p.store()
			},
			failure: AttestationFailureCDContent,
		},
		{
			name: "Basic Information unknown", ids: defaultPKIIDs, cd: defaultTestCD, mode: AttestationDevelopment,
			tweak: func(c *attestationCase, p *attestationPKI) AttestationTrustStore {
				c.hasIDs = false
				return p.store()
			},
			failure: AttestationFailureMalformed,
		},
		{
			name: "none ignores unknown Basic Information", ids: defaultPKIIDs, cd: defaultTestCD, mode: AttestationNone,
			tweak: func(c *attestationCase, p *attestationPKI) AttestationTrustStore {
				c.hasIDs = false
				return p.store()
			},
		},
		{
			name: "device is another product of the vendor", ids: defaultPKIIDs, cd: defaultTestCD, mode: AttestationDevelopment,
			tweak: func(c *attestationCase, p *attestationPKI) AttestationTrustStore {
				c.pid = 0x8002
				return p.store()
			},
			failure: AttestationFailureCDContent,
		},
		{
			name: "DAC origin does not bind another product", ids: defaultPKIIDs, cd: testCD{vid: 0xFFF4, pids: []uint16{0x9000}, origin: &[2]uint16{0xFFF2, 0x8001}}, mode: AttestationDevelopment,
			tweak: func(c *attestationCase, p *attestationPKI) AttestationTrustStore {
				c.vid, c.pid = 0xFFF2, 0x8001 // the DAC's product, not the certified one
				return p.store()
			},
			failure: AttestationFailureCDContent,
		},
		{
			name: "rejected PAA", ids: prodIDs, cd: prodCD, mode: AttestationProduction,
			opts:    nil,
			tweak:   func(_ *attestationCase, p *attestationPKI) AttestationTrustStore { return p.store() },
			failure: AttestationFailureRejectedAnchor,
		},
		{
			name: "rejected CD signer", ids: prodIDs, cd: prodCD, mode: AttestationProduction,
			opts:    nil,
			tweak:   func(_ *attestationCase, p *attestationPKI) AttestationTrustStore { return p.store() },
			failure: AttestationFailureRejectedAnchor,
		},
		{name: "CD format version 2", ids: defaultPKIIDs, cd: testCD{vid: 0xFFF2, pids: []uint16{0x8001}, formatVersion: 2}, mode: AttestationDevelopment, failure: AttestationFailureMalformed},
		{name: "CD without device type", ids: defaultPKIIDs, cd: testCD{vid: 0xFFF2, pids: []uint16{0x8001}, omitDeviceType: true}, mode: AttestationDevelopment, failure: AttestationFailureMalformed},
		{name: "CD with a short certificate ID", ids: defaultPKIIDs, cd: testCD{vid: 0xFFF2, pids: []uint16{0x8001}, certificateID: "ZIG20141"}, mode: AttestationDevelopment, failure: AttestationFailureMalformed},
		{name: "revoked", ids: defaultPKIIDs, cd: defaultTestCD, mode: AttestationDevelopment, opts: []AttestationVerifierOption{WithAttestationRevocationChecker(revokeAll{})}, failure: AttestationFailureRevoked},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pki := newAttestationPKI(t, tt.ids)
			c := newAttestationCase(t, pki, tt.cd)
			store := pki.store()
			if tt.tweak != nil {
				store = tt.tweak(c, pki)
			}
			opts := tt.opts
			switch tt.name {
			case "rejected PAA":
				opts = append(opts, WithAttestationRejectedAnchors(NewAttestationTrustStore([]*x509.Certificate{pki.paa}, nil)))
			case "rejected CD signer":
				opts = append(opts, WithAttestationRejectedAnchors(NewAttestationTrustStore(nil, []*x509.Certificate{pki.cdSigner})))
			}
			err := NewAttestationVerifier(tt.mode, store, opts...).VerifyAttestation(c.info(t))
			if tt.failure == 0 {
				if err != nil {
					t.Fatalf("VerifyAttestation() error = %v, want nil", err)
				}
				return
			}
			var ae *AttestationError
			if !errors.As(err, &ae) || !errors.Is(err, ErrAttestation) {
				t.Fatalf("VerifyAttestation() error = %v, want an AttestationError", err)
			}
			if ae.Failure != tt.failure {
				t.Fatalf("VerifyAttestation() failure = %v (%v), want %v", ae.Failure, err, tt.failure)
			}
		})
	}
}

func TestParseAttestationMode(t *testing.T) {
	for _, mode := range []AttestationMode{AttestationDevelopment, AttestationProduction, AttestationNone} {
		got, err := ParseAttestationMode(mode.String())
		if err != nil || got != mode {
			t.Errorf("ParseAttestationMode(%q) = %v, %v; want %v", mode.String(), got, err, mode)
		}
	}
	if _, err := ParseAttestationMode("strict"); err == nil {
		t.Error("ParseAttestationMode(\"strict\") error = nil, want an error")
	}
}

func TestAttestationIDFromCommonName(t *testing.T) {
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: "ACME Matter Devel DAC 5CDA9899 Mvid:FFF1 Mpid:00B1"}}
	vid, okV, errV := attestationVendorID(cert)
	pid, okP, errP := attestationProductID(cert)
	if errV != nil || errP != nil || !okV || !okP || vid != 0xFFF1 || pid != 0x00B1 {
		t.Fatalf("IDs from common name = %04X %v %v, %04X %v %v", vid, okV, errV, pid, okP, errP)
	}
}

func TestAttestationTrustStoreKeepsPAAsAndCDSignersApart(t *testing.T) {
	pki := newAttestationPKI(t, defaultPKIIDs)
	// A test CD signing certificate may be a self-signed CA like a PAA, so
	// the store takes each kind from its own list.
	selfSignedCD := pki.issue("Test CD Signing Authority", "", "", true, nil, nil, newTestKey(t), false)
	store, err := ParseAttestationTrustStore([][]byte{pki.paa.Raw, pki.paa.Raw}, [][]byte{pki.cdSigner.Raw, selfSignedCD.Raw})
	if err != nil {
		t.Fatal(err)
	}
	if got := len(store.PAAs()); got != 1 {
		t.Errorf("PAAs() = %d certificates, want 1", got)
	}
	if got := len(store.CDSigningCertificates()); got != 2 {
		t.Errorf("CDSigningCertificates() = %d certificates, want 2", got)
	}
	merged := MergeAttestationTrustStores(store, nil, NewAttestationTrustStore([]*x509.Certificate{pki.paa}, nil))
	if got := len(merged.PAAs()); got != 1 {
		t.Errorf("merged PAAs() = %d certificates, want 1", got)
	}
}

func ExampleIsTestVendorID() {
	fmt.Println(IsTestVendorID(0xFFF1), IsTestVendorID(0x1234))
	// Output: true false
}
