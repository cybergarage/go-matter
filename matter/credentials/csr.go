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

// Package credentials provides the commissioner-side pieces of the
// Operational Credentials flow that sit above the raw Matter-TLV certificate
// codec in matter/credentials/chipcert: parsing the NOCSRElements and
// AttestationElements structures returned by the Operational Credentials
// cluster's CSRRequest/AttestationRequest commands, verifying their DAC
// signatures, and a minimal commissioner-side certificate authority that
// issues Node Operational Certificates from a device's CSR.
package credentials

import (
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"

	"github.com/cybergarage/go-matter/matter/encoding/tlv"
)

// NOCSRElements TLV field tags.
// Matter Core Spec 6.4.6.1. NOCSR Elements, connectedhomeip
// src/credentials/DeviceAttestationConstructor.cpp (OperationalCSRInfoId).
const (
	tagCSR             = 1
	tagCSRNonce        = 2
	tagVendorReserved1 = 3
	tagVendorReserved2 = 4
	tagVendorReserved3 = 5
	csrNonceLength     = 32
)

// NOCSRElements is the decoded content of the octstr NOCSRElements field
// returned by the Operational Credentials cluster's CSRResponse command
// (11.18.7.6. CSRResponse Command).
type NOCSRElements struct {
	// CSR is the raw PKCS#10 CertificationRequest (DER), not itself further
	// Matter-TLV-encoded.
	CSR []byte
	// CSRNonce echoes the nonce sent in the CSRRequest command.
	CSRNonce []byte
}

// ParseNOCSRElements decodes a Matter-TLV NOCSRElements structure.
func ParseNOCSRElements(tlvBytes []byte) (NOCSRElements, error) {
	dec := tlv.NewDecoderWithBytes(tlvBytes)
	if !dec.Next() {
		if err := dec.Error(); err != nil {
			return NOCSRElements{}, fmt.Errorf("credentials: NOCSRElements: %w", err)
		}
		return NOCSRElements{}, fmt.Errorf("credentials: NOCSRElements: empty payload")
	}
	if !dec.Element().Type().IsStructure() {
		return NOCSRElements{}, fmt.Errorf("credentials: NOCSRElements: expected top-level Structure")
	}

	var out NOCSRElements
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			break
		}
		ct, ok := elem.Tag().(tlv.ContextTag)
		if !ok {
			continue
		}
		switch ct.ContextNumber() {
		case tagCSR:
			b, ok := elem.Bytes()
			if !ok {
				return NOCSRElements{}, fmt.Errorf("credentials: NOCSRElements: csr is not an octet string")
			}
			out.CSR = b
		case tagCSRNonce:
			b, ok := elem.Bytes()
			if !ok {
				return NOCSRElements{}, fmt.Errorf("credentials: NOCSRElements: csrNonce is not an octet string")
			}
			out.CSRNonce = b
		}
	}
	if err := dec.Error(); err != nil {
		return NOCSRElements{}, fmt.Errorf("credentials: NOCSRElements: %w", err)
	}
	if len(out.CSR) == 0 {
		return NOCSRElements{}, fmt.Errorf("credentials: NOCSRElements: missing csr")
	}
	if len(out.CSRNonce) != csrNonceLength {
		return NOCSRElements{}, fmt.Errorf("credentials: NOCSRElements: missing or invalid csrNonce")
	}
	return out, nil
}

// VerifyNOCSRElementsSignature verifies the AttestationSignature returned
// alongside NOCSRElements by the CSRResponse command. The signature is
// computed by the device over the concatenation of the raw NOCSRElements TLV
// bytes and the session's AttestationChallenge, using its DAC private key.
// 11.18.7.6. CSRResponse Command.
func VerifyNOCSRElementsSignature(nocsrElementsTLV, attestationChallenge, sig []byte, dacPub *ecdsa.PublicKey) error {
	msg := make([]byte, 0, len(nocsrElementsTLV)+len(attestationChallenge))
	msg = append(msg, nocsrElementsTLV...)
	msg = append(msg, attestationChallenge...)
	if err := verifyRawSignature(dacPub, msg, sig); err != nil {
		return fmt.Errorf("credentials: verify NOCSRElements signature: %w", err)
	}
	return nil
}

// ParseCSR parses a raw PKCS#10 CertificationRequest (as extracted from
// NOCSRElements.CSR) and validates its self-signature.
func ParseCSR(pkcs10DER []byte) (*x509.CertificateRequest, error) {
	csr, err := x509.ParseCertificateRequest(pkcs10DER)
	if err != nil {
		return nil, fmt.Errorf("credentials: parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("credentials: CSR signature invalid: %w", err)
	}
	return csr, nil
}
