// Copyright (C) 2024 The go-matter Authors. All rights reserved.
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

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	rootKeyFile  = "admin-root-key.pem"
	rootCertFile = "admin-root-cert.pem"
	adminKeyFile = "admin-private-key.pem"
	adminNOCFile = "admin-noc.pem"
)

var (
	oidCommonName     = asn1.ObjectIdentifier{2, 5, 4, 3}
	matterNodeIDOID   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37244, 1, 1}
	matterRCACIDOID   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37244, 1, 4}
	matterFabricIDOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37244, 1, 5}

	// oidExtKeyUsage, oidKeyPurposeClientAuth and oidKeyPurposeServerAuth are
	// used to build the ExtKeyUsage extension by hand via ExtraExtensions —
	// see extKeyUsageClientServerAuthExtension's doc comment for why.
	oidExtKeyUsage          = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidKeyPurposeServerAuth = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	oidKeyPurposeClientAuth = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
)

// utf8Attr builds a DN attribute whose value is explicitly tagged as an
// ASN.1 UTF8String, rather than left to encoding/asn1's default heuristic
// (which picks PrintableString for content — like our all-digit Matter ID
// hex strings, or a plain CommonName — that happens to fit PrintableString's
// narrower character set). connectedhomeip's own certificate reconstruction
// (src/credentials/CHIPCert.cpp ChipDN::EncodeToASN1) always emits
// UTF8String for the Matter custom 64-bit DN attributes (NodeID, FabricID,
// RCACId, ...), and our own chipcert TLV encoder always emits CommonName as
// UTF8String too (chipcert.go's encodeRDN); a certificate signed with
// PrintableString for either produces different DER bytes than what a
// device reconstructs from the TLV, silently invalidating the signature — a
// real device rejected AddTrustedRootCertificate with InvalidCommand for
// exactly this reason (RCACId), even after every structural requirement
// (Subject attribute presence, SubjectKeyId/AuthorityKeyId equality,
// extension order) was already satisfied.
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
// A cert signed over Go's non-critical encoding therefore has different TBS
// bytes than what a device reconstructs from the equivalent TLV, breaking
// the chain signature.
//
// Both purposes, not just clientAuth: this admin NOC used to carry only
// clientAuth, since the administrator only ever acts as CASE's initiator in
// this codebase. But a real device's own CASE handling
// (CASESession.cpp's mValidContext, used identically for both Sigma2's
// responder NOC and Sigma3's initiator NOC) unconditionally requires
// KeyPurposeFlags::kServerAuth on any NOC validated during CASE, regardless
// of which side sent it — a real device accepted Sigma1/Sigma2 fine but
// rejected Sigma3 with StatusReport{FAILURE, INVALID_PARAMETER} until this
// admin NOC also carried serverAuth, matching every operational NOC's
// requirement (Matter Core Spec 6.5.3) to carry both key purposes.
func extKeyUsageClientServerAuthExtension() (pkix.Extension, error) {
	val, err := asn1.Marshal([]asn1.ObjectIdentifier{oidKeyPurposeClientAuth, oidKeyPurposeServerAuth})
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("marshal ExtKeyUsage: %w", err)
	}
	return pkix.Extension{Id: oidExtKeyUsage, Critical: true, Value: val}, nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	adminNodeIDHex, err := matterHexEnv("ADMIN_NODE_ID_HEX", "0000000000000001")
	if err != nil {
		return err
	}
	fabricIDHex, err := matterHexEnv("FABRIC_ID_HEX", "0000000000000002")
	if err != nil {
		return err
	}
	days, err := intEnv("DAYS", 36500)
	if err != nil {
		return err
	}

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("root key: %w", err)
	}
	adminKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("administrator key: %w", err)
	}
	rootSerial, err := serialNumber()
	if err != nil {
		return err
	}
	adminSerial, err := serialNumber()
	if err != nil {
		return err
	}

	now := time.Now()

	// RFC 5280 ยง4.2.1.2 method (1): SKID = SHA-1(subjectPublicKey BIT STRING
	// content). Computed explicitly for both certs, rather than left for
	// x509.CreateCertificate to auto-generate: the root is self-signed
	// (parent == template), and Go only auto-copies a parent's SubjectKeyId
	// into the issued cert's AuthorityKeyId when the parent is a distinct,
	// already-populated certificate, not when signing a certificate with
	// itself — so its own AuthorityKeyId needs this value set up front too.
	// Matter requires an RCAC's AuthorityKeyId to equal its own SubjectKeyId
	// (connectedhomeip's ValidateChipRCAC), and requires the Subject DN to
	// carry the MatterRCACId attribute for the certificate to be recognized
	// as a root ("GetCertType" in src/credentials/CHIPCert.cpp) — a real
	// device rejected AddTrustedRootCertificate with InvalidCommand for
	// missing both. Separately, connectedhomeip's ChipCertificateSet::LoadCert
	// rejects ANY certificate — including a non-CA leaf NOC — that lacks a
	// SubjectKeyId extension, regardless of whether anything else references
	// it (CHIP_ERROR_UNSUPPORTED_CERT_FORMAT); the admin NOC needs its own
	// SubjectKeyId set for the same reason, even though nothing signs beneath
	// it. The admin NOC's BasicConstraintsValid is set true (IsCA left
	// false) for the same reason as matter/credentials/ca.go's IssueNOC:
	// connectedhomeip's own reference X.509 generator
	// (src/credentials/GenerateChipX509Cert.cpp EncodeNOCSpecificExtensions)
	// always emits a (content-empty) BasicConstraints extension for a NOC,
	// which Go's x509.CreateCertificate omits entirely unless
	// BasicConstraintsValid is set.
	rootPubKeyBytes := elliptic.Marshal(rootKey.PublicKey.Curve, rootKey.PublicKey.X, rootKey.PublicKey.Y)
	rootSKID := sha1.Sum(rootPubKeyBytes)
	adminPubKeyBytes := elliptic.Marshal(adminKey.PublicKey.Curve, adminKey.PublicKey.X, adminKey.PublicKey.Y)
	adminSKID := sha1.Sum(adminPubKeyBytes)

	rootTemplate := &x509.Certificate{
		SerialNumber: rootSerial,
		Subject: pkix.Name{
			ExtraNames: []pkix.AttributeTypeAndValue{
				utf8Attr(oidCommonName, "go-matter Test Administrator Root CA"),
				utf8Attr(matterRCACIDOID, "0000000000000001"),
			},
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Duration(days) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          rootSKID[:],
		AuthorityKeyId:        rootSKID[:],
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		return fmt.Errorf("root certificate: %w", err)
	}

	adminEKU, err := extKeyUsageClientServerAuthExtension()
	if err != nil {
		return err
	}
	adminTemplate := &x509.Certificate{
		SerialNumber: adminSerial,
		Subject: pkix.Name{
			ExtraNames: []pkix.AttributeTypeAndValue{
				utf8Attr(oidCommonName, "go-matter Test Administrator"),
				utf8Attr(matterNodeIDOID, adminNodeIDHex),
				utf8Attr(matterFabricIDOID, fabricIDHex),
			},
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Duration(days) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtraExtensions:       []pkix.Extension{adminEKU},
		BasicConstraintsValid: true,
		IsCA:                  false,
		SubjectKeyId:          adminSKID[:],
		AuthorityKeyId:        rootSKID[:],
	}
	adminNOCDER, err := x509.CreateCertificate(rand.Reader, adminTemplate, rootTemplate, &adminKey.PublicKey, rootKey)
	if err != nil {
		return fmt.Errorf("administrator NOC: %w", err)
	}
	adminKeyDER, err := x509.MarshalPKCS8PrivateKey(adminKey)
	if err != nil {
		return fmt.Errorf("administrator private key: %w", err)
	}
	rootKeyDER, err := x509.MarshalECPrivateKey(rootKey)
	if err != nil {
		return fmt.Errorf("root private key: %w", err)
	}

	if err := writePEM(rootKeyFile, 0o600, "EC PRIVATE KEY", rootKeyDER); err != nil {
		return err
	}
	if err := writePEM(rootCertFile, 0o644, "CERTIFICATE", rootDER); err != nil {
		return err
	}
	if err := writePEM(adminKeyFile, 0o600, "PRIVATE KEY", adminKeyDER); err != nil {
		return err
	}
	if err := writePEM(adminNOCFile, 0o644, "CERTIFICATE", adminNOCDER); err != nil {
		return err
	}
	return nil
}

func matterHexEnv(name, fallback string) (string, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		raw = fallback
	}
	raw = strings.TrimPrefix(strings.ToLower(raw), "0x")
	raw = strings.ToUpper(raw)
	if len(raw) > 16 {
		return "", fmt.Errorf("%s must fit in 64 bits", name)
	}
	raw = strings.Repeat("0", 16-len(raw)) + raw
	if _, err := hex.DecodeString(raw); err != nil {
		return "", fmt.Errorf("%s must be hexadecimal: %w", name, err)
	}
	return raw, nil
}

func intEnv(name string, fallback int) (int, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer: %w", name, err)
	}
	if n <= 0 {
		return 0, fmt.Errorf("%s must be greater than zero", name)
	}
	return n, nil
}

func serialNumber() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("serial number: %w", err)
	}
	return serial, nil
}

func writePEM(path string, perm os.FileMode, typ string, der []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: typ, Bytes: der}); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}
