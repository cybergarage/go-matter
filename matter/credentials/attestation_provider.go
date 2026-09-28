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
	"errors"
	"fmt"

	"github.com/cybergarage/go-matter/matter/encoding/tlv"
)

// AttestationProvider holds what a device proves its origin with during
// commissioning (Matter Core 6.2): its Device Attestation Certificate (DAC),
// the Product Attestation Intermediate (PAI) which issued it, its
// Certification Declaration (CD), and the DAC's private key, which it only
// signs with.
//
// A product is provisioned with its own at manufacture. The
// credentials/testcreds package provides the public test ones of the Matter
// SDK, which only commissioners in development mode accept.
type AttestationProvider interface {
	// DAC returns the DER-encoded Device Attestation Certificate.
	DAC() []byte
	// PAI returns the DER-encoded Product Attestation Intermediate
	// certificate which issued the DAC.
	PAI() []byte
	// CertificationDeclaration returns the CMS-signed Certification
	// Declaration.
	CertificationDeclaration() []byte
	// FirmwareInformation returns the optional firmware information; nil
	// when there is none.
	FirmwareInformation() []byte
	// SignWithDAC signs msg with the DAC's private key (Crypto_Sign).
	SignWithDAC(msg []byte) ([]byte, error)
}

type attestationProvider struct {
	dac, pai, cd, firmware []byte
	signer                 Signer
}

// NewAttestationProvider returns an AttestationProvider for the given DAC,
// PAI and CD, signing with dacSigner, which must hold the DAC's key.
// firmware may be nil.
func NewAttestationProvider(dac, pai, cd, firmware []byte, dacSigner Signer) (AttestationProvider, error) {
	cert, err := x509.ParseCertificate(dac)
	if err != nil {
		return nil, fmt.Errorf("credentials: parse the DAC: %w", err)
	}
	if _, err := x509.ParseCertificate(pai); err != nil {
		return nil, fmt.Errorf("credentials: parse the PAI: %w", err)
	}
	if len(cd) == 0 {
		return nil, errors.New("credentials: the Certification Declaration is empty")
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || dacSigner == nil || !pub.Equal(dacSigner.PublicKey()) {
		return nil, errors.New("credentials: the signer does not hold the DAC's key")
	}
	return &attestationProvider{dac: dac, pai: pai, cd: cd, firmware: firmware, signer: dacSigner}, nil
}

func (p *attestationProvider) DAC() []byte                      { return p.dac }
func (p *attestationProvider) PAI() []byte                      { return p.pai }
func (p *attestationProvider) CertificationDeclaration() []byte { return p.cd }
func (p *attestationProvider) FirmwareInformation() []byte      { return p.firmware }

func (p *attestationProvider) SignWithDAC(msg []byte) ([]byte, error) {
	return p.signer.Sign(msg)
}

// BuildAttestationElements encodes the AttestationElements a device
// answers an AttestationRequest with (Matter Core 6.4.5.1, 11.18.6.2):
// the CD, the commissioner's nonce, the timestamp, and the optional
// firmware information.
func BuildAttestationElements(cd, nonce []byte, timestamp uint32, firmware []byte) ([]byte, error) {
	if len(nonce) != attestationNonceLength {
		return nil, fmt.Errorf("credentials: the attestation nonce is %d bytes, want %d", len(nonce), attestationNonceLength)
	}
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	if err := enc.PutOctet(tlv.NewContextTag(tagCertificationDeclaration), cd); err != nil {
		return nil, err
	}
	if err := enc.PutOctet(tlv.NewContextTag(tagAttestationNonce), nonce); err != nil {
		return nil, err
	}
	enc.PutUnsigned4(tlv.NewContextTag(tagAttestationTimestamp), timestamp)
	if 0 < len(firmware) {
		if err := enc.PutOctet(tlv.NewContextTag(tagFirmwareInfo), firmware); err != nil {
			return nil, err
		}
	}
	if err := enc.EndContainer(); err != nil {
		return nil, err
	}
	return enc.Bytes(), nil
}

// BuildNOCSRElements encodes the NOCSRElements a device answers a
// CSRRequest with (Matter Core 6.4.6.1, 11.18.6.6): the CSR and the
// commissioner's nonce.
func BuildNOCSRElements(csr, nonce []byte) ([]byte, error) {
	if len(nonce) != csrNonceLength {
		return nil, fmt.Errorf("credentials: the CSR nonce is %d bytes, want %d", len(nonce), csrNonceLength)
	}
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	if err := enc.PutOctet(tlv.NewContextTag(tagCSR), csr); err != nil {
		return nil, err
	}
	if err := enc.PutOctet(tlv.NewContextTag(tagCSRNonce), nonce); err != nil {
		return nil, err
	}
	if err := enc.EndContainer(); err != nil {
		return nil, err
	}
	return enc.Bytes(), nil
}

// SignWithChallenge returns sign's signature over elements followed by the
// session's attestation challenge, as AttestationResponse and CSRResponse
// carry (11.18.6.2, 11.18.6.6).
func SignWithChallenge(sign func([]byte) ([]byte, error), elements, challenge []byte) ([]byte, error) {
	msg := make([]byte, 0, len(elements)+len(challenge))
	msg = append(msg, elements...)
	msg = append(msg, challenge...)
	return sign(msg)
}
