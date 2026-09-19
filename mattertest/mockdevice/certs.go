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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"
)

// attestationIdentity holds the mock device's synthetic Device Attestation
// Certificate (DAC) and Product Attestation Intermediate (PAI) certificate,
// returned to a commissioner via CertificateChainRequest and used to sign
// AttestationResponse/CSRResponse.
type attestationIdentity struct {
	dacPriv    *ecdsa.PrivateKey
	dacCertDER []byte
	paiCertDER []byte
}

// generateAttestationIdentity creates a fresh, self-signed synthetic DAC/PAI
// pair for this mock device, regenerated on every call (no fixed fixture
// files, unlike mattertest/certs' admin material).
//
// Neither cert needs to chain to anything resembling a real Product
// Attestation Authority: this repo's own commissioner
// (matter/commissioning_impl.go's commissionDeviceAttestation) deliberately
// only verifies the DAC's own signature over AttestationElements/
// NOCSRElements plus the PASE attestation challenge — it never validates a
// DAC -> PAI -> PAA chain of trust or the Certification Declaration. So a
// self-signed DAC and an unrelated self-signed PAI, with no Matter-specific
// extensions, are sufficient here.
func generateAttestationIdentity() (attestationIdentity, error) {
	dacPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return attestationIdentity{}, fmt.Errorf("mockdevice: generate DAC key: %w", err)
	}
	dacSerial, err := randomSerialNumber()
	if err != nil {
		return attestationIdentity{}, err
	}
	now := time.Now()
	dacTemplate := &x509.Certificate{
		SerialNumber: dacSerial,
		Subject:      pkix.Name{CommonName: "go-matter mock device DAC"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	dacDER, err := x509.CreateCertificate(rand.Reader, dacTemplate, dacTemplate, &dacPriv.PublicKey, dacPriv)
	if err != nil {
		return attestationIdentity{}, fmt.Errorf("mockdevice: create DAC certificate: %w", err)
	}

	paiPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return attestationIdentity{}, fmt.Errorf("mockdevice: generate PAI key: %w", err)
	}
	paiSerial, err := randomSerialNumber()
	if err != nil {
		return attestationIdentity{}, err
	}
	paiTemplate := &x509.Certificate{
		SerialNumber:          paiSerial,
		Subject:               pkix.Name{CommonName: "go-matter mock device PAI"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	paiDER, err := x509.CreateCertificate(rand.Reader, paiTemplate, paiTemplate, &paiPriv.PublicKey, paiPriv)
	if err != nil {
		return attestationIdentity{}, fmt.Errorf("mockdevice: create PAI certificate: %w", err)
	}

	return attestationIdentity{
		dacPriv:    dacPriv,
		dacCertDER: dacDER,
		paiCertDER: paiDER,
	}, nil
}

func randomSerialNumber() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("mockdevice: generate serial number: %w", err)
	}
	return serial, nil
}
