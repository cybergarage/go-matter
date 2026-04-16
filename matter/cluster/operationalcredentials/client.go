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

// Package operationalcredentials provides a client skeleton for the Matter
// Operational Credentials cluster (0x003E).
// Reference: Matter Core Spec 1.5, Section 11.18.
//
// # Implementation status
//
// The full Operational Credentials flow requires substantial PKI infrastructure
// that is not yet present in this repository:
//
//   - AttestationRequest / AttestationResponse parsing
//   - CertificateChainRequest (DAC / PAI) and X.509 certificate chain verification
//   - CSRRequest and ECDSA-with-SHA256 signature over TBSCertificate
//   - Root CA management and NOC (Node Operational Certificate) generation
//   - AddTrustedRootCertificate and AddNOC command encoding
//
// TODO: Implement the full attestation and operational credentials flow once the
// Matter certificate (Matter TLV-encoded X.509) and PKI primitives are available.
package operationalcredentials

import (
	"errors"

	"github.com/cybergarage/go-matter/matter/protocol/im"
	"github.com/cybergarage/go-matter/matter/protocol/session"
)

// ClusterID is the Operational Credentials cluster identifier.
// 11.18. Operational Credentials Cluster.
const ClusterID im.ClusterID = 0x003E

// Command IDs for the Operational Credentials cluster.
// 11.18.7. Commands.
const (
	// AttestationRequestCommandID requests attestation information from the device.
	AttestationRequestCommandID im.CommandID = 0x00
	// CertificateChainRequestCommandID requests a DAC or PAI certificate from the device.
	CertificateChainRequestCommandID im.CommandID = 0x02
	// CSRRequestCommandID requests a Certificate Signing Request from the device.
	CSRRequestCommandID im.CommandID = 0x04
	// AddNOCCommandID adds a new Node Operational Certificate to the device.
	AddNOCCommandID im.CommandID = 0x06
	// AddTrustedRootCertificateCommandID adds a trusted root certificate to the device.
	AddTrustedRootCertificateCommandID im.CommandID = 0x0B
)

// ErrNotImplemented is returned by unimplemented PKI operations.
var ErrNotImplemented = errors.New("operationalcredentials: not yet implemented — Matter PKI infrastructure required")

// AttestationRequest sends an AttestationRequest command to the device and returns
// the raw AttestationResponse payload bytes.
// 11.18.7.1. AttestationRequest Command.
//
// TODO: Implement full attestation challenge verification against the device's DAC.
func AttestationRequest(_ session.SecureSession, _ im.EndpointID, _ []byte) ([]byte, error) {
	return nil, ErrNotImplemented
}

// CertificateChainRequest requests a certificate (DAC or PAI) from the device.
// certificateType: 1 = DAC, 2 = PAI.
// 11.18.7.3. CertificateChainRequest Command.
//
// TODO: Implement with Matter TLV certificate parsing and X.509 chain validation.
func CertificateChainRequest(_ session.SecureSession, _ im.EndpointID, _ uint8) ([]byte, error) {
	return nil, ErrNotImplemented
}

// CSRRequest requests a Certificate Signing Request from the device.
// 11.18.7.5. CSRRequest Command.
//
// TODO: Implement with Matter CSR encoding and ECDSA signature verification.
func CSRRequest(_ session.SecureSession, _ im.EndpointID, _ []byte) ([]byte, error) {
	return nil, ErrNotImplemented
}

// AddTrustedRootCertificate adds a trusted root certificate (commissioner's RCAC) to the device.
// 11.18.7.11. AddTrustedRootCertificate Command.
//
// TODO: Implement once Root CA certificate generation is available.
func AddTrustedRootCertificate(_ session.SecureSession, _ im.EndpointID, _ []byte) error {
	return ErrNotImplemented
}

// AddNOC provisions the device with a Node Operational Certificate, completing fabric joining.
// 11.18.7.6. AddNOC Command.
//
// TODO: Implement once NOC generation and IPK derivation are available.
func AddNOC(_ session.SecureSession, _ im.EndpointID, _ []byte, _ []byte, _ []byte, _ uint64, _ uint16) error {
	return ErrNotImplemented
}
