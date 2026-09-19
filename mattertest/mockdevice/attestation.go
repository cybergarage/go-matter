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
	"crypto/ecdsa"
	"fmt"

	"github.com/cybergarage/go-matter/matter/crypto"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
)

// rawSignatureLen is the length of a raw (r||s) P-256 ECDSA signature, per
// spec 3.5.3 — matching matter/credentials.verifyRawSignature's expected
// wire format for AttestationResponse/CSRResponse signatures.
const rawSignatureLen = 64

// signRaw signs msg with priv and returns the signature as a fixed-width
// 64-byte r||s encoding (each right-aligned/zero-padded to 32 bytes) — the
// same generic ECDSA raw-signature convention this repo's CASE client uses
// for Sigma2/Sigma3 (marshalSignature in matter/protocol/case/crypto.go),
// reimplemented independently here since that helper is unexported.
func signRaw(priv *ecdsa.PrivateKey, msg []byte) ([]byte, error) {
	sig, err := crypto.CryptoSign(crypto.NewPrivateKey(priv), msg)
	if err != nil {
		return nil, fmt.Errorf("mockdevice: sign: %w", err)
	}
	out := make([]byte, rawSignatureLen)
	r, s := sig.R(), sig.S()
	copy(out[32-len(r):32], r)
	copy(out[64-len(s):64], s)
	return out, nil
}

// AttestationElements TLV field tags, matching matter/credentials.ParseAttestationElements.
// Matter Core Spec 6.4.5.1. Attestation Elements.
const (
	tagCertificationDeclaration = 1
	tagAttestationNonce         = 2
	tagAttestationTimestamp     = 3
)

// encodeAttestationElements builds the AttestationElements TLV structure
// returned by AttestationResponse. FirmwareInfo (tag 4) is omitted — it's
// optional and matter/credentials.ParseAttestationElements doesn't require
// it.
func encodeAttestationElements(certificationDeclaration, nonce []byte, timestamp uint32) ([]byte, error) {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	if err := enc.PutOctet(tlv.NewContextTag(tagCertificationDeclaration), certificationDeclaration); err != nil {
		return nil, err
	}
	if err := enc.PutOctet(tlv.NewContextTag(tagAttestationNonce), nonce); err != nil {
		return nil, err
	}
	enc.PutUnsigned4(tlv.NewContextTag(tagAttestationTimestamp), timestamp)
	if err := enc.EndContainer(); err != nil {
		return nil, err
	}
	return enc.Bytes(), nil
}

// NOCSRElements TLV field tags, matching matter/credentials.ParseNOCSRElements.
// Matter Core Spec 6.4.6.1. NOCSR Elements.
const (
	tagCSR      = 1
	tagCSRNonce = 2
)

// encodeNOCSRElements builds the NOCSRElements TLV structure returned by
// CSRResponse.
func encodeNOCSRElements(csrDER, csrNonce []byte) ([]byte, error) {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	if err := enc.PutOctet(tlv.NewContextTag(tagCSR), csrDER); err != nil {
		return nil, err
	}
	if err := enc.PutOctet(tlv.NewContextTag(tagCSRNonce), csrNonce); err != nil {
		return nil, err
	}
	if err := enc.EndContainer(); err != nil {
		return nil, err
	}
	return enc.Bytes(), nil
}
