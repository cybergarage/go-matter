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
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/cybergarage/go-logger/log"
)

// AttestationMode selects how strictly a commissioner verifies device
// attestation (6.2.3. Device Attestation Procedure).
type AttestationMode int

const (
	// AttestationDevelopment runs the whole procedure against a trust
	// store which may hold test and self-issued anchors besides the
	// production ones, and accepts the test vendor IDs. It is the default,
	// so that both certified products and devices under development are
	// commissioned.
	AttestationDevelopment AttestationMode = iota
	// AttestationProduction runs the whole procedure against production
	// anchors only, and rejects the test vendor IDs and Certification
	// Declarations for development and test.
	AttestationProduction
	// AttestationNone only checks that the device holds the key of the DAC
	// it presents and echoes the nonce; it does not verify the chain of
	// trust or the Certification Declaration. Use it only for devices
	// which are trusted otherwise.
	AttestationNone
)

// String returns the name of the mode, as ParseAttestationMode takes it.
func (m AttestationMode) String() string {
	switch m {
	case AttestationDevelopment:
		return "development"
	case AttestationProduction:
		return "production"
	case AttestationNone:
		return "none"
	default:
		return fmt.Sprintf("AttestationMode(%d)", int(m))
	}
}

// ParseAttestationMode returns the mode named "development", "production"
// or "none".
func ParseAttestationMode(s string) (AttestationMode, error) {
	switch s {
	case "development":
		return AttestationDevelopment, nil
	case "production":
		return AttestationProduction, nil
	case "none":
		return AttestationNone, nil
	default:
		return 0, fmt.Errorf("credentials: unknown attestation mode %q", s)
	}
}

// AttestationInfo is what a commissioner learns about a device during
// device attestation (11.18.7. Operational Credentials cluster commands).
type AttestationInfo struct {
	// DAC and PAI are the DER-encoded certificates returned by
	// CertificateChainRequest.
	DAC []byte
	PAI []byte
	// AttestationElements and AttestationSignature are the fields of the
	// AttestationResponse.
	AttestationElements  []byte
	AttestationSignature []byte
	// AttestationChallenge is the challenge of the session the response
	// was received over.
	AttestationChallenge []byte
	// AttestationNonce is the nonce sent in the AttestationRequest.
	AttestationNonce []byte
}

// AttestationVerifier verifies the attestation of a device. A commissioner
// stops commissioning a device whose attestation does not verify.
type AttestationVerifier interface {
	VerifyAttestation(info AttestationInfo) error
}

// RevocationChecker reports whether a DAC or a PAI has been revoked, such
// as with the revocation set of the Distributed Compliance Ledger. It
// returns an error for a revoked certificate.
type RevocationChecker interface {
	CheckRevocation(dac, pai *x509.Certificate) error
}

// AttestationFailure tells why an attestation was rejected.
type AttestationFailure int

const (
	AttestationFailureMalformed AttestationFailure = iota + 1
	AttestationFailureSignature
	AttestationFailureNonce
	AttestationFailureVendorID
	AttestationFailureProductID
	AttestationFailureTestVendorID
	AttestationFailurePAANotFound
	AttestationFailureChain
	AttestationFailureCDSignerNotFound
	AttestationFailureCDSignature
	AttestationFailureCDContent
	AttestationFailureRevoked
)

func (f AttestationFailure) String() string {
	switch f {
	case AttestationFailureMalformed:
		return "malformed"
	case AttestationFailureSignature:
		return "signature"
	case AttestationFailureNonce:
		return "nonce"
	case AttestationFailureVendorID:
		return "vendor ID"
	case AttestationFailureProductID:
		return "product ID"
	case AttestationFailureTestVendorID:
		return "test vendor ID"
	case AttestationFailurePAANotFound:
		return "PAA not found"
	case AttestationFailureChain:
		return "certificate chain"
	case AttestationFailureCDSignerNotFound:
		return "CD signer not found"
	case AttestationFailureCDSignature:
		return "CD signature"
	case AttestationFailureCDContent:
		return "CD content"
	case AttestationFailureRevoked:
		return "revoked"
	default:
		return fmt.Sprintf("AttestationFailure(%d)", int(f))
	}
}

// ErrAttestation is wrapped by every AttestationError.
var ErrAttestation = errors.New("credentials: device attestation failed")

// AttestationError is returned by an AttestationVerifier which rejected a
// device. errors.Is(err, ErrAttestation) holds for it.
type AttestationError struct {
	Failure AttestationFailure
	Err     error
}

func (e *AttestationError) Error() string {
	return fmt.Sprintf("%v (%v): %v", ErrAttestation, e.Failure, e.Err)
}

func (e *AttestationError) Unwrap() []error {
	return []error{ErrAttestation, e.Err}
}

func attestationError(f AttestationFailure, format string, args ...any) error {
	return &AttestationError{Failure: f, Err: fmt.Errorf(format, args...)}
}

// AttestationVerifierOption configures an AttestationVerifier.
type AttestationVerifierOption func(*attestationVerifier)

// WithAttestationRevocationChecker sets the revocation check run on the DAC
// and the PAI. Without one, revocation is not checked.
func WithAttestationRevocationChecker(c RevocationChecker) AttestationVerifierOption {
	return func(v *attestationVerifier) {
		v.revocation = c
	}
}

// WithAttestationClock sets the clock the validity of the certificates is
// checked against. Defaults to time.Now.
func WithAttestationClock(now func() time.Time) AttestationVerifierOption {
	return func(v *attestationVerifier) {
		v.now = now
	}
}

type attestationVerifier struct {
	mode       AttestationMode
	store      AttestationTrustStore
	revocation RevocationChecker
	now        func() time.Time
}

// NewAttestationVerifier returns an AttestationVerifier which verifies in
// the given mode against the given trust store. The store is not used in
// AttestationNone.
func NewAttestationVerifier(mode AttestationMode, store AttestationTrustStore, opts ...AttestationVerifierOption) AttestationVerifier {
	v := &attestationVerifier{mode: mode, store: store, revocation: nil, now: time.Now}
	if v.store == nil {
		v.store = NewAttestationTrustStore(nil, nil)
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// IsTestVendorID reports whether vid is one of the vendor IDs reserved for
// testing, 0xFFF1 to 0xFFF4 (2.5.2. Vendor Identifier).
func IsTestVendorID(vid uint16) bool {
	return 0xFFF1 <= vid && vid <= 0xFFF4
}

// VerifyAttestation runs the device attestation procedure (6.2.3.1).
func (v *attestationVerifier) VerifyAttestation(info AttestationInfo) error {
	dac, err := x509.ParseCertificate(info.DAC)
	if err != nil {
		return attestationError(AttestationFailureMalformed, "parse the DAC: %w", err)
	}
	dacKey, ok := dac.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return attestationError(AttestationFailureMalformed, "the DAC key is not ECDSA")
	}
	// The device proves that it holds the DAC's key by signing the
	// attestation elements with the session's challenge
	// (11.18.7.2. AttestationResponse Command).
	if err := VerifyAttestationSignature(info.AttestationElements, info.AttestationChallenge, info.AttestationSignature, dacKey); err != nil {
		return attestationError(AttestationFailureSignature, "%w", err)
	}
	elements, err := ParseAttestationElements(info.AttestationElements)
	if err != nil {
		return attestationError(AttestationFailureMalformed, "%w", err)
	}
	if !bytes.Equal(elements.Nonce, info.AttestationNonce) {
		return attestationError(AttestationFailureNonce, "the AttestationResponse does not echo the AttestationNonce")
	}
	if v.mode == AttestationNone {
		log.Warnf("credentials: device attestation: the chain of trust and the Certification Declaration are not verified (mode %v)", v.mode)
		return nil
	}

	pai, err := x509.ParseCertificate(info.PAI)
	if err != nil {
		return attestationError(AttestationFailureMalformed, "parse the PAI: %w", err)
	}
	vid, pid, err := checkAttestationIDs(dac, pai)
	if err != nil {
		return err
	}
	if IsTestVendorID(vid) {
		if v.mode == AttestationProduction {
			return attestationError(AttestationFailureTestVendorID, "the DAC has the test vendor ID 0x%04X", vid)
		}
		log.Warnf("credentials: device attestation: accepting the test vendor ID 0x%04X (mode %v)", vid, v.mode)
	}

	paa, err := v.verifyChain(dac, pai)
	if err != nil {
		return err
	}
	paaVID, hasPAAVID, err := attestationVendorID(paa)
	if err != nil {
		return attestationError(AttestationFailureMalformed, "the PAA: %w", err)
	}
	if hasPAAVID && paaVID != vid {
		return attestationError(AttestationFailureVendorID, "the PAA has vendor ID 0x%04X, the PAI 0x%04X", paaVID, vid)
	}

	if err := v.verifyCertificationDeclaration(elements.CertificationDeclaration, vid, pid, paa); err != nil {
		return err
	}

	if v.revocation != nil {
		if err := v.revocation.CheckRevocation(dac, pai); err != nil {
			return attestationError(AttestationFailureRevoked, "%w", err)
		}
	}
	return nil
}

// checkAttestationIDs returns the vendor ID and the product ID of the DAC
// after checking that the PAI agrees with them (6.2.2.2, 6.2.2.3).
func checkAttestationIDs(dac, pai *x509.Certificate) (uint16, uint16, error) {
	vid, hasVID, err := attestationVendorID(dac)
	if err != nil {
		return 0, 0, attestationError(AttestationFailureMalformed, "the DAC: %w", err)
	}
	pid, hasPID, err := attestationProductID(dac)
	if err != nil {
		return 0, 0, attestationError(AttestationFailureMalformed, "the DAC: %w", err)
	}
	if !hasVID || !hasPID {
		return 0, 0, attestationError(AttestationFailureMalformed, "the DAC has no vendor ID or no product ID")
	}
	paiVID, hasPAIVID, err := attestationVendorID(pai)
	if err != nil {
		return 0, 0, attestationError(AttestationFailureMalformed, "the PAI: %w", err)
	}
	if !hasPAIVID {
		return 0, 0, attestationError(AttestationFailureMalformed, "the PAI has no vendor ID")
	}
	if paiVID != vid {
		return 0, 0, attestationError(AttestationFailureVendorID, "the PAI has vendor ID 0x%04X, the DAC 0x%04X", paiVID, vid)
	}
	paiPID, hasPAIPID, err := attestationProductID(pai)
	if err != nil {
		return 0, 0, attestationError(AttestationFailureMalformed, "the PAI: %w", err)
	}
	if hasPAIPID && paiPID != pid {
		return 0, 0, attestationError(AttestationFailureProductID, "the PAI has product ID 0x%04X, the DAC 0x%04X", paiPID, pid)
	}
	return vid, pid, nil
}

// verifyChain verifies DAC -> PAI -> PAA against the trusted PAAs and
// returns the PAA (6.2.3.1).
func (v *attestationVerifier) verifyChain(dac, pai *x509.Certificate) (*x509.Certificate, error) {
	roots := x509.NewCertPool()
	for _, paa := range v.store.PAAs() {
		roots.AddCert(paa)
	}
	intermediates := x509.NewCertPool()
	intermediates.AddCert(pai)
	chains, err := dac.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   v.now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		var unknown x509.UnknownAuthorityError
		if errors.As(err, &unknown) {
			return nil, attestationError(AttestationFailurePAANotFound,
				"no trusted PAA issued the PAI %q (authority key ID %X); add it to the attestation trust store: %w",
				pai.Subject.CommonName, pai.AuthorityKeyId, err)
		}
		return nil, attestationError(AttestationFailureChain, "%w", err)
	}
	for _, chain := range chains {
		// A DAC is issued by a PAI, which is issued by a PAA (6.2.2).
		if len(chain) == 3 && chain[1].Equal(pai) {
			return chain[2], nil
		}
	}
	return nil, attestationError(AttestationFailureChain, "the DAC does not chain to a trusted PAA through its PAI")
}

// verifyCertificationDeclaration verifies the signature and the content of
// the Certification Declaration against the DAC's IDs (6.3, 6.2.3.1).
func (v *attestationVerifier) verifyCertificationDeclaration(der []byte, vid, pid uint16, paa *x509.Certificate) error {
	signed, err := ParseSignedCertificationDeclaration(der)
	if err != nil {
		return attestationError(AttestationFailureMalformed, "%w", err)
	}
	var signer *x509.Certificate
	for _, c := range v.store.CDSigningCertificates() {
		if bytes.Equal(c.SubjectKeyId, signed.SignerKeyID) {
			signer = c
			break
		}
	}
	if signer == nil {
		return attestationError(AttestationFailureCDSignerNotFound,
			"no trusted Certification Declaration signing certificate has key ID %X", signed.SignerKeyID)
	}
	if err := signed.Verify(signer); err != nil {
		return attestationError(AttestationFailureCDSignature, "%w", err)
	}
	cd, err := ParseCertificationDeclaration(signed.Content)
	if err != nil {
		return attestationError(AttestationFailureMalformed, "%w", err)
	}
	if v.mode == AttestationProduction && cd.CertificationType == CertificationTypeDevelopmentAndTest {
		return attestationError(AttestationFailureCDContent, "the Certification Declaration is for development and test")
	}
	if cd.HasDACOrigin {
		// The product carries the DAC of another vendor's product.
		if cd.DACOriginVendorID != vid || cd.DACOriginProductID != pid {
			return attestationError(AttestationFailureCDContent,
				"the Certification Declaration names DAC origin 0x%04X/0x%04X, the DAC is 0x%04X/0x%04X",
				cd.DACOriginVendorID, cd.DACOriginProductID, vid, pid)
		}
	} else {
		if cd.VendorID != vid {
			return attestationError(AttestationFailureCDContent,
				"the Certification Declaration names vendor ID 0x%04X, the DAC 0x%04X", cd.VendorID, vid)
		}
		if !containsUint16(cd.ProductIDs, pid) {
			return attestationError(AttestationFailureCDContent,
				"the Certification Declaration does not list the DAC's product ID 0x%04X", pid)
		}
	}
	if len(cd.AuthorizedPAAs) != 0 {
		authorized := false
		for _, id := range cd.AuthorizedPAAs {
			if bytes.Equal(id, paa.SubjectKeyId) {
				authorized = true
				break
			}
		}
		if !authorized {
			return attestationError(AttestationFailureCDContent,
				"the Certification Declaration does not authorize the PAA %X", paa.SubjectKeyId)
		}
	}
	return nil
}

func containsUint16(list []uint16, v uint16) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// Matter DN attributes of attestation certificates (6.2.2.2).
var (
	oidMatterVendorID  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37244, 2, 1}
	oidMatterProductID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37244, 2, 2}
	// A legacy certificate may carry the IDs in its common name instead,
	// as "Mvid:FFF1" and "Mpid:8000" (6.2.2.2).
	commonNameVendorID  = regexp.MustCompile(`Mvid:([0-9A-F]{4})`)
	commonNameProductID = regexp.MustCompile(`Mpid:([0-9A-F]{4})`)
)

func attestationVendorID(cert *x509.Certificate) (uint16, bool, error) {
	return attestationID(cert, oidMatterVendorID, commonNameVendorID)
}

func attestationProductID(cert *x509.Certificate) (uint16, bool, error) {
	return attestationID(cert, oidMatterProductID, commonNameProductID)
}

// attestationID reads a 16-bit ID, a 4-digit uppercase hex string, from
// the subject attribute oid, or else from the common name.
func attestationID(cert *x509.Certificate, oid asn1.ObjectIdentifier, cn *regexp.Regexp) (uint16, bool, error) {
	for _, atv := range cert.Subject.Names {
		if !atv.Type.Equal(oid) {
			continue
		}
		s, ok := atv.Value.(string)
		if !ok {
			return 0, false, fmt.Errorf("subject attribute %v is not a string", oid)
		}
		return parseAttestationID(s, oid)
	}
	if m := cn.FindStringSubmatch(cert.Subject.CommonName); m != nil {
		return parseAttestationID(m[1], oid)
	}
	return 0, false, nil
}

func parseAttestationID(s string, oid asn1.ObjectIdentifier) (uint16, bool, error) {
	if len(s) != 4 {
		return 0, false, fmt.Errorf("subject attribute %v is %q, not 4 hex digits", oid, s)
	}
	v, err := strconv.ParseUint(s, 16, 16)
	if err != nil {
		return 0, false, fmt.Errorf("subject attribute %v is %q, not 4 hex digits", oid, s)
	}
	return uint16(v), true, nil
}
