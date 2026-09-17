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
	"crypto/rand"
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
)

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
// (see mattertest/certs/certgen.go). The returned certificate is DER-encoded
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
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			ExtraNames: []pkix.AttributeTypeAndValue{
				{Type: oidMatterNodeID, Value: uint64ToHexRDNValue(nodeID)},
				{Type: oidMatterFabricID, Value: uint64ToHexRDNValue(ca.fabricID)},
			},
		},
		NotBefore:   now.Add(-time.Hour),
		NotAfter:    now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
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
