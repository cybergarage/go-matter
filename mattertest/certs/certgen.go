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

	// matterEpoch (2000-01-01T00:00:00Z, spec 5.6.1 "Epoch Time") is used as
	// NotBefore instead of time.Now(): a freshly commissioned or
	// factory-reset device commonly has no synced clock yet (no
	// battery-backed RTC, no NTP, nothing set by the commissioner until
	// later) and would see a NotBefore stamped with today's real date as a
	// certificate "from the future," rejecting it. connectedhomeip's own
	// reference commissioner-side CA (src/controller/
	// ExampleOperationalCredentialsIssuer.h) defaults its "current time"
	// field to exactly this for the same reason (mNow = 0, i.e. Matter
	// epoch second 0) rather than the host's wall clock. A real device's
	// AddNOC rejected the administrator NOC generated here with the generic
	// NodeOperationalCertStatusEnum::kInvalidNOC for this reason.
	now := time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)

	// RFC 5280 ยง4.2.1.2 method (1): SKID = SHA-1(subjectPublicKey BIT STRING
	// content). Computed explicitly, rather than left for x509.CreateCertificate
	// to auto-generate, because a self-signed certificate (parent == template)
	// needs its AuthorityKeyId set to this same value up front — Go only
	// auto-copies a parent's SubjectKeyId into the issued cert's
	// AuthorityKeyId when the parent is a distinct, already-populated
	// certificate, not when signing a certificate with itself. Matter
	// requires an RCAC's AuthorityKeyId to equal its own SubjectKeyId
	// (connectedhomeip's ValidateChipRCAC), and requires the Subject DN to
	// carry the MatterRCACId attribute for the certificate to be recognized
	// as a root ("GetCertType" in src/credentials/CHIPCert.cpp) — a real
	// device rejected AddTrustedRootCertificate with InvalidCommand for
	// missing both.
	rootPubKeyBytes := elliptic.Marshal(rootKey.PublicKey.Curve, rootKey.PublicKey.X, rootKey.PublicKey.Y)
	rootSKID := sha1.Sum(rootPubKeyBytes)

	rootTemplate := &x509.Certificate{
		SerialNumber: rootSerial,
		Subject: pkix.Name{
			ExtraNames: []pkix.AttributeTypeAndValue{
				utf8Attr(oidCommonName, "go-matter Test Administrator Root CA"),
				utf8Attr(matterRCACIDOID, "0000000000000001"),
			},
		},
		NotBefore:             now,
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

	adminTemplate := &x509.Certificate{
		SerialNumber: adminSerial,
		Subject: pkix.Name{
			ExtraNames: []pkix.AttributeTypeAndValue{
				utf8Attr(oidCommonName, "go-matter Test Administrator"),
				utf8Attr(matterNodeIDOID, adminNodeIDHex),
				utf8Attr(matterFabricIDOID, fabricIDHex),
			},
		},
		NotBefore:      now,
		NotAfter:       now.Add(time.Duration(days) * 24 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		AuthorityKeyId: rootSKID[:],
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
