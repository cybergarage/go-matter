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
	"fmt"

	"github.com/cybergarage/go-matter/matter/encoding/tlv"
)

// AttestationElements TLV field tags.
// Matter Core Spec 6.4.5.1. Attestation Elements, connectedhomeip
// src/credentials/DeviceAttestationConstructor.cpp (AttestationInfoId).
const (
	tagCertificationDeclaration = 1
	tagAttestationNonce         = 2
	tagAttestationTimestamp     = 3
	tagFirmwareInfo             = 4

	attestationNonceLength = 32
)

// AttestationElements is the decoded content of the octstr AttestationElements
// field returned by the Operational Credentials cluster's AttestationResponse
// command (11.18.7.2. AttestationResponse Command).
//
// # Implementation status
//
// This codebase performs only a pragmatic, signature-only check of
// AttestationElements: it verifies that the response was signed by the
// device's own DAC private key (see VerifyAttestationSignature), so the
// commissioner knows it is really talking to the holder of that key. It does
// NOT validate the Certification Declaration's signature against the CSA's
// CD signing certificate, and does NOT build or verify a DAC -> PAI -> PAA
// chain of trust against a Product Attestation Authority trust store. This
// is intentionally out of scope — see the go-matter commissioning plan this
// package was built against — and is not suitable for production/certified
// commissioner use, only for commissioning a device the operator already
// trusts (e.g. their own hardware in a local/test setting).
type AttestationElements struct {
	// CertificationDeclaration is the device's signed Certification
	// Declaration, opaque to this package (not further parsed or verified).
	CertificationDeclaration []byte
	// Nonce echoes the AttestationNonce sent in the AttestationRequest command.
	Nonce []byte
	// Timestamp is the device's epoch-time timestamp for this attestation.
	Timestamp uint32
	// FirmwareInfo is optional device firmware information, empty if absent.
	FirmwareInfo []byte
}

// ParseAttestationElements decodes a Matter-TLV AttestationElements structure.
func ParseAttestationElements(tlvBytes []byte) (AttestationElements, error) {
	dec := tlv.NewDecoderWithBytes(tlvBytes)
	if !dec.Next() {
		if err := dec.Error(); err != nil {
			return AttestationElements{}, fmt.Errorf("credentials: AttestationElements: %w", err)
		}
		return AttestationElements{}, fmt.Errorf("credentials: AttestationElements: empty payload")
	}
	if !dec.Element().Type().IsStructure() {
		return AttestationElements{}, fmt.Errorf("credentials: AttestationElements: expected top-level Structure")
	}

	var (
		out    AttestationElements
		haveTS bool
	)
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
		case tagCertificationDeclaration:
			b, ok := elem.Bytes()
			if !ok {
				return AttestationElements{}, fmt.Errorf("credentials: AttestationElements: certificationDeclaration is not an octet string")
			}
			out.CertificationDeclaration = b
		case tagAttestationNonce:
			b, ok := elem.Bytes()
			if !ok {
				return AttestationElements{}, fmt.Errorf("credentials: AttestationElements: attestationNonce is not an octet string")
			}
			out.Nonce = b
		case tagAttestationTimestamp:
			v, ok := elem.Unsigned4()
			if !ok {
				return AttestationElements{}, fmt.Errorf("credentials: AttestationElements: timestamp is not an integer")
			}
			out.Timestamp = v
			haveTS = true
		case tagFirmwareInfo:
			b, ok := elem.Bytes()
			if !ok {
				return AttestationElements{}, fmt.Errorf("credentials: AttestationElements: firmwareInfo is not an octet string")
			}
			out.FirmwareInfo = b
		}
	}
	if err := dec.Error(); err != nil {
		return AttestationElements{}, fmt.Errorf("credentials: AttestationElements: %w", err)
	}
	if len(out.CertificationDeclaration) == 0 {
		return AttestationElements{}, fmt.Errorf("credentials: AttestationElements: missing certificationDeclaration")
	}
	if len(out.Nonce) != attestationNonceLength {
		return AttestationElements{}, fmt.Errorf("credentials: AttestationElements: missing or invalid attestationNonce")
	}
	if !haveTS {
		return AttestationElements{}, fmt.Errorf("credentials: AttestationElements: missing timestamp")
	}
	return out, nil
}

// VerifyAttestationSignature verifies the AttestationSignature returned
// alongside AttestationElements by the AttestationResponse command. The
// signature is computed by the device over the concatenation of the raw
// AttestationElements TLV bytes and the session's AttestationChallenge,
// using its DAC private key. See the package doc comment for the scope of
// verification this codebase performs (signature-only, no chain of trust).
// 11.18.7.2. AttestationResponse Command.
func VerifyAttestationSignature(attestationElementsTLV, attestationChallenge, sig []byte, dacPub *ecdsa.PublicKey) error {
	msg := make([]byte, 0, len(attestationElementsTLV)+len(attestationChallenge))
	msg = append(msg, attestationElementsTLV...)
	msg = append(msg, attestationChallenge...)
	if err := verifyRawSignature(dacPub, msg, sig); err != nil {
		return fmt.Errorf("credentials: verify AttestationElements signature: %w", err)
	}
	return nil
}
