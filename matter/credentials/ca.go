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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// Matter custom-OID DN attributes, matching matter/protocol/case/crypto.go's
// matterNodeIDOID/matterFabricIDOID convention (enterprise OID
// 1.3.6.1.4.1.37244.1.{1,5}, values encoded as a 16-character uppercase hex
// string rather than a native ASN.1 INTEGER).
var (
	oidMatterNodeID   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37244, 1, 1}
	oidMatterFabricID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37244, 1, 5}

	// oidExtKeyUsage, oidKeyPurposeClientAuth and oidKeyPurposeServerAuth
	// are used to build the ExtKeyUsage extension by hand via
	// ExtraExtensions instead of x509.Certificate's ExtKeyUsage convenience
	// field — see extKeyUsageClientServerAuthExtension's doc comment for why.
	oidExtKeyUsage          = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidKeyPurposeServerAuth = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	oidKeyPurposeClientAuth = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
)

// utf8Attr builds a DN attribute whose value is explicitly tagged as an
// ASN.1 UTF8String, rather than left to encoding/asn1's default heuristic
// (which picks PrintableString for an all-hex-digit string like these
// Matter ID values). connectedhomeip's own certificate reconstruction
// (src/credentials/CHIPCert.cpp ChipDN::EncodeToASN1) always emits
// UTF8String for the Matter custom 64-bit DN attributes; a NOC signed with
// PrintableString here would produce different DER bytes than what a device
// reconstructs from the equivalent TLV, invalidating the chain signature —
// see mattertest/certs/certgen.go's identical helper for how this was found
// (a real device rejected AddTrustedRootCertificate over exactly this for
// the root cert's own RCACId attribute).
func utf8Attr(oid asn1.ObjectIdentifier, s string) pkix.AttributeTypeAndValue {
	return pkix.AttributeTypeAndValue{
		Type:  oid,
		Value: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagUTF8String, Bytes: []byte(s)},
	}
}

// extKeyUsageClientServerAuthExtension builds a ready-to-use ExtraExtensions
// entry for ExtKeyUsage{clientAuth, serverAuth}, marked critical, for use
// instead of x509.Certificate's ExtKeyUsage convenience field. Go's
// x509.CreateCertificate always marks that field's extension non-critical,
// but connectedhomeip's device-side TLV-to-X509 reconstruction
// (src/credentials/CHIPCertToX509.cpp DecodeConvertExtension) unconditionally
// treats ExtKeyUsage (along with KeyUsage and BasicConstraints) as critical
// when rebuilding the TBS bytes it hashes for signature verification —
// confirmed by connectedhomeip's own DER-to-TLV converter
// (src/credentials/CHIPCertFromX509.cpp ConvertExtension) explicitly
// requiring critical=true for the same extension when going the other way.
// A NOC signed over Go's non-critical encoding therefore has different TBS
// bytes than what a device reconstructs from the equivalent TLV, breaking
// the chain signature — invisible to this package's own round-trip
// self-checks because chipcert.TLVToDER made the identical omission, so
// re-deriving DER from our own TLV output stayed self-consistent even
// though it diverged from what a real device independently reconstructs.
func extKeyUsageClientServerAuthExtension() (pkix.Extension, error) {
	val, err := asn1.Marshal([]asn1.ObjectIdentifier{oidKeyPurposeClientAuth, oidKeyPurposeServerAuth})
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("credentials: marshal ExtKeyUsage: %w", err)
	}
	return pkix.Extension{Id: oidExtKeyUsage, Critical: true, Value: val}, nil
}

// CertificateAuthority is a minimal commissioner-side CA: it holds the
// administrator's own root key pair and signs Node Operational Certificates
// for devices being commissioned, from the CSR they return in CSRResponse.
//
// This mirrors mattertest/certs/certgen.go's certificate generation
// approach, extended to sign a CSR-supplied public key instead of a locally
// generated one, and to embed a Matter NodeID chosen by the commissioner
// (types.NewOperationalNodeID) rather than a fixed test value.
type CertificateAuthority struct {
	rootCert *x509.Certificate
	rootKey  *ecdsa.PrivateKey
	fabricID uint64
}

// NewCertificateAuthority constructs a CertificateAuthority from the
// administrator's root certificate and its private key (both accepting PEM
// or DER, matching the encodings config.AdministratorConfig documents for
// RootCertificate()/PrivateKey()), and the target fabric ID.
func NewCertificateAuthority(rootCertBytes, rootPrivateKeyBytes []byte, fabricID uint64) (*CertificateAuthority, error) {
	rootDER, err := certificateDERBytes(rootCertBytes)
	if err != nil {
		return nil, fmt.Errorf("credentials: root certificate: %w", err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return nil, fmt.Errorf("credentials: parse root certificate: %w", err)
	}
	rootKey, err := parsePrivateKey(rootPrivateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("credentials: root private key: %w", err)
	}
	rootPub, ok := rootCert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !rootPub.Equal(&rootKey.PublicKey) {
		return nil, fmt.Errorf("credentials: root private key does not match root certificate's public key")
	}
	if fabricID == 0 {
		return nil, fmt.Errorf("credentials: fabric ID is required")
	}
	return &CertificateAuthority{rootCert: rootCert, rootKey: rootKey, fabricID: fabricID}, nil
}

// IssueNOC signs a Node Operational Certificate binding the given CSR's
// public key to nodeID on this CA's fabric, matching the Matter custom-OID
// Subject RDN convention this repo already uses for administrator NOCs
// (see mattertest/certs/certgen.go). AuthorityKeyId is set explicitly to
// ca.rootCert.SubjectKeyId rather than left for x509.CreateCertificate to
// derive: certificate chain validation looks up the issuing CA by matching
// (IssuerDN, AuthorityKeyId) against a candidate's (SubjectDN,
// SubjectKeyId) (connectedhomeip's ChipCertificateSet::FindValidCert), so an
// unset AuthorityKeyId on the issued NOC would fail chain validation during
// CASE. SubjectKeyId is likewise set explicitly (RFC 5280 §4.2.1.2 method 1:
// SHA-1 of the subjectPublicKey BIT STRING content), rather than left unset:
// connectedhomeip's ChipCertificateSet::LoadCert rejects ANY certificate
// (including the leaf NOC, not just CAs) with CHIP_ERROR_UNSUPPORTED_CERT_FORMAT
// unless BOTH the SubjectKeyId and AuthorityKeyId extensions are present — a
// real device rejected AddNOC with NOCResponse status=3 (InvalidNOC) for
// exactly this reason. BasicConstraintsValid is likewise set explicitly
// (with IsCA left false): connectedhomeip's own reference X.509 generator
// (src/credentials/GenerateChipX509Cert.cpp EncodeNOCSpecificExtensions)
// always emits a BasicConstraints extension for a NOC, even though it's
// empty content for a non-CA cert — Go's x509.CreateCertificate omits the
// extension entirely unless BasicConstraintsValid is set, producing a NOC
// whose Extensions list structurally differs from every other successfully
// commissioning implementation's. The returned certificate is DER-encoded
// X.509; convert it to the Matter-TLV wire format with
// matter/credentials/chipcert.DERToTLV before sending it via AddNOC.
func (ca *CertificateAuthority) IssueNOC(csr *x509.CertificateRequest, nodeID uint64) ([]byte, error) {
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("credentials: CSR public key is not ECDSA")
	}

	serial, err := randomSerialNumber()
	if err != nil {
		return nil, err
	}
	pubKeyBytes := elliptic.Marshal(pub.Curve, pub.X, pub.Y)
	subjectKeyID := sha1.Sum(pubKeyBytes)
	ekuExt, err := extKeyUsageClientServerAuthExtension()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			ExtraNames: []pkix.AttributeTypeAndValue{
				utf8Attr(oidMatterNodeID, uint64ToHexRDNValue(nodeID)),
				utf8Attr(oidMatterFabricID, uint64ToHexRDNValue(ca.fabricID)),
			},
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtraExtensions:       []pkix.Extension{ekuExt},
		BasicConstraintsValid: true,
		IsCA:                  false,
		SubjectKeyId:          subjectKeyID[:],
		AuthorityKeyId:        ca.rootCert.SubjectKeyId,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.rootCert, pub, ca.rootKey)
	if err != nil {
		return nil, fmt.Errorf("credentials: issue NOC: %w", err)
	}
	return der, nil
}

// RootCertificateDER returns the CA's root certificate, DER-encoded. This is
// the RCAC sent via AddTrustedRootCertificate (after chipcert.DERToTLV).
func (ca *CertificateAuthority) RootCertificateDER() []byte {
	return append([]byte(nil), ca.rootCert.Raw...)
}

func randomSerialNumber() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("credentials: generate serial number: %w", err)
	}
	return serial, nil
}

func uint64ToHexRDNValue(v uint64) string {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return strings.ToUpper(hex.EncodeToString(b))
}

func certificateDERBytes(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("empty certificate")
	}
	if block, _ := pem.Decode(b); block != nil {
		return block.Bytes, nil
	}
	return b, nil
}

func parsePrivateKey(b []byte) (*ecdsa.PrivateKey, error) {
	if block, _ := pem.Decode(b); block != nil {
		b = block.Bytes
	}
	if key, err := x509.ParsePKCS8PrivateKey(b); err == nil {
		ecdsaKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("unsupported PKCS#8 private key type %T", key)
		}
		return ecdsaKey, nil
	}
	if key, err := x509.ParseECPrivateKey(b); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("unsupported private key encoding")
}
