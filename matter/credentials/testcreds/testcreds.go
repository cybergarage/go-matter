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

// Package testcreds provides the public test attestation credentials of the
// Matter SDK (project-chip/connectedhomeip), which its example applications
// use: the DAC for vendor ID 0xFFF1 and product ID 0x8000, the PAI which
// issued it, the test PAA, and a Certification Declaration covering that
// vendor. See certs/README.md for their exact source and license.
//
// They are for development and testing only: the DAC's private key is
// public, and commissioners accept them only in development mode, such as
// chip-tool with its default test trust store.
package testcreds

import (
	_ "embed"

	"github.com/cybergarage/go-matter/matter/credentials"
)

// The vendor and product the credentials are issued for. The
// Certification Declaration covers the product IDs 0x8000 to 0x8063.
const (
	VendorID  uint16 = 0xFFF1
	ProductID uint16 = 0x8000
)

var (
	//go:embed certs/Matter-Development-DAC-FFF1-8000-Cert.der
	dacCert []byte
	//go:embed certs/Matter-Development-DAC-FFF1-8000-Key.der
	dacKey []byte
	//go:embed certs/Matter-Development-PAI-FFF1-noPID-Cert.der
	paiCert []byte
	//go:embed certs/Chip-Test-PAA-FFF1-Cert.der
	paaCert []byte
	//go:embed certs/Chip-Example-CD-FFF1.der
	certificationDeclaration []byte
	//go:embed certs/CSA_Matter_CD_Signing_Key_001.cert.der
	cdSigningCert []byte
)

// AttestationProvider returns the test DAC, PAI and CD, signing with the
// test DAC's key.
func AttestationProvider() (credentials.AttestationProvider, error) {
	signer, err := credentials.ParseSoftwareSigner(dacKey)
	if err != nil {
		return nil, err
	}
	return credentials.NewAttestationProvider(clone(dacCert), clone(paiCert), clone(certificationDeclaration), nil, signer)
}

// PAA returns the DER-encoded test Product Attestation Authority
// certificate at the root of the DAC's chain, which a commissioner trusts
// in development mode.
func PAA() []byte {
	return clone(paaCert)
}

// CDSigningCertificate returns the DER-encoded certificate of the key which
// signed the Certification Declaration.
func CDSigningCertificate() []byte {
	return clone(cdSigningCert)
}

func clone(b []byte) []byte {
	return append([]byte(nil), b...)
}
