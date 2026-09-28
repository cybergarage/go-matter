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
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"strconv"

	"github.com/cybergarage/go-matter/matter/credentials/chipcert"
)

// Matter RDN attributes a device reads from its operational certificates
// (Matter Core 6.5.6.1).
var (
	oidMatterICACID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37244, 1, 3}
	oidMatterRCACID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37244, 1, 4}
)

// Operational node ID ranges (Matter Core 2.5.5): an operational node ID is
// 0x0000_0000_0000_0001..0xFFFF_FFEF_FFFF_FFFF, and a CASE Authenticated Tag
// subject is 0xFFFF_FFFD_xxxx_xxxx with a non-zero version.
const (
	maxOperationalNodeID uint64 = 0xFFFF_FFEF_FFFF_FFFF
	catSubjectPrefix     uint64 = 0xFFFF_FFFD_0000_0000
	catSubjectMask       uint64 = 0xFFFF_FFFF_0000_0000
	catVersionMask       uint64 = 0x0000_0000_0000_FFFF
)

// IsOperationalNodeID reports whether id is in the operational node ID
// range.
func IsOperationalNodeID(id uint64) bool {
	return 0 < id && id <= maxOperationalNodeID
}

// IsCASEAuthenticatedTag reports whether id is a CASE Authenticated Tag
// subject with a valid (non-zero) version.
func IsCASEAuthenticatedTag(id uint64) bool {
	return id&catSubjectMask == catSubjectPrefix && id&catVersionMask != 0
}

// ErrInvalidOperationalCertificate is wrapped by the errors of
// ParseOperationalCertificate and VerifyOperationalChain.
var ErrInvalidOperationalCertificate = errors.New("credentials: invalid operational certificate")

// OperationalCertificate is a Matter operational certificate (an RCAC,
// ICAC or NOC) together with the Matter identifiers of its subject.
type OperationalCertificate struct {
	// TLV is the certificate in the Matter TLV encoding it was parsed from.
	TLV []byte
	// Certificate is the X.509 form chipcert.TLVToDER reconstructs, over
	// which the signature is computed.
	Certificate *x509.Certificate
	// PublicKey is the subject's key, uncompressed (65 bytes).
	PublicKey []byte
	// NodeID is the subject's node ID; 0 when it has none (an RCAC or
	// ICAC).
	NodeID uint64
	// FabricID is the subject's fabric ID; 0 when it has none, which is
	// optional in an RCAC and ICAC.
	FabricID uint64
}

// ParseOperationalCertificate parses a certificate in the Matter TLV
// encoding (Matter Core 6.5), as AddTrustedRootCertificate and AddNOC carry
// them.
func ParseOperationalCertificate(tlvBytes []byte) (*OperationalCertificate, error) {
	der, err := chipcert.TLVToDER(tlvBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidOperationalCertificate, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidOperationalCertificate, err)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: public key is %T, not ECDSA", ErrInvalidOperationalCertificate, cert.PublicKey)
	}
	ecdhPub, err := pub.ECDH()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidOperationalCertificate, err)
	}
	oc := &OperationalCertificate{
		TLV:         append([]byte(nil), tlvBytes...),
		Certificate: cert,
		PublicKey:   ecdhPub.Bytes(),
		NodeID:      0,
		FabricID:    0,
	}
	if oc.NodeID, _, err = subjectUint64(cert, oidMatterNodeID); err != nil {
		return nil, err
	}
	if oc.FabricID, _, err = subjectUint64(cert, oidMatterFabricID); err != nil {
		return nil, err
	}
	return oc, nil
}

// subjectUint64 reads a Matter 64-bit subject attribute, a 16-digit hex
// string.
func subjectUint64(cert *x509.Certificate, oid asn1.ObjectIdentifier) (uint64, bool, error) {
	for _, atv := range cert.Subject.Names {
		if !atv.Type.Equal(oid) {
			continue
		}
		s, ok := atv.Value.(string)
		if !ok || len(s) != 16 {
			return 0, false, fmt.Errorf("%w: subject attribute %v is %v, not a 16-digit hex string", ErrInvalidOperationalCertificate, oid, atv.Value)
		}
		v, err := strconv.ParseUint(s, 16, 64)
		if err != nil {
			return 0, false, fmt.Errorf("%w: subject attribute %v: %w", ErrInvalidOperationalCertificate, oid, err)
		}
		return v, true, nil
	}
	return 0, false, nil
}

func hasSubjectAttribute(cert *x509.Certificate, oid asn1.ObjectIdentifier) bool {
	for _, atv := range cert.Subject.Names {
		if atv.Type.Equal(oid) {
			return true
		}
	}
	return false
}

// VerifyRootCertificate checks that rcac is a Matter root CA certificate:
// a self-signed CA certificate with an RCAC ID (Matter Core 6.5.11).
func VerifyRootCertificate(rcac *OperationalCertificate) error {
	cert := rcac.Certificate
	if !cert.BasicConstraintsValid || !cert.IsCA {
		return fmt.Errorf("%w: the root certificate is not a CA", ErrInvalidOperationalCertificate)
	}
	if !hasSubjectAttribute(cert, oidMatterRCACID) {
		return fmt.Errorf("%w: the root certificate has no RCAC ID", ErrInvalidOperationalCertificate)
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		return fmt.Errorf("%w: the root certificate is not self-signed: %w", ErrInvalidOperationalCertificate, err)
	}
	return nil
}

// VerifyOperationalChain checks that noc chains to rcac, through icac when
// it is not nil (Matter Core 6.5.11): each certificate is signed by the
// next, the NOC is a leaf with an operational node ID and a fabric ID, the
// ICAC is a CA with an ICAC ID, and every fabric ID the chain carries
// matches the NOC's. Validity periods are not checked: a device does not
// necessarily know the time while it is being commissioned.
func VerifyOperationalChain(noc, icac, rcac *OperationalCertificate) error {
	if err := VerifyRootCertificate(rcac); err != nil {
		return err
	}
	leaf := noc.Certificate
	if leaf.BasicConstraintsValid && leaf.IsCA {
		return fmt.Errorf("%w: the NOC is a CA certificate", ErrInvalidOperationalCertificate)
	}
	if !IsOperationalNodeID(noc.NodeID) {
		return fmt.Errorf("%w: the NOC's node ID 0x%016X is not operational", ErrInvalidOperationalCertificate, noc.NodeID)
	}
	if noc.FabricID == 0 {
		return fmt.Errorf("%w: the NOC has no fabric ID", ErrInvalidOperationalCertificate)
	}
	issuer := rcac
	if icac != nil {
		if !icac.Certificate.BasicConstraintsValid || !icac.Certificate.IsCA {
			return fmt.Errorf("%w: the ICAC is not a CA", ErrInvalidOperationalCertificate)
		}
		if !hasSubjectAttribute(icac.Certificate, oidMatterICACID) {
			return fmt.Errorf("%w: the ICAC has no ICAC ID", ErrInvalidOperationalCertificate)
		}
		if icac.FabricID != 0 && icac.FabricID != noc.FabricID {
			return fmt.Errorf("%w: the ICAC's fabric ID differs from the NOC's", ErrInvalidOperationalCertificate)
		}
		if err := icac.Certificate.CheckSignatureFrom(rcac.Certificate); err != nil {
			return fmt.Errorf("%w: the ICAC is not signed by the root: %w", ErrInvalidOperationalCertificate, err)
		}
		issuer = icac
	}
	if rcac.FabricID != 0 && rcac.FabricID != noc.FabricID {
		return fmt.Errorf("%w: the root's fabric ID differs from the NOC's", ErrInvalidOperationalCertificate)
	}
	if err := leaf.CheckSignatureFrom(issuer.Certificate); err != nil {
		return fmt.Errorf("%w: the NOC is not signed by its issuer: %w", ErrInvalidOperationalCertificate, err)
	}
	return nil
}
