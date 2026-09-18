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

// Package operationalcredentials provides a client for the Matter
// Operational Credentials cluster (0x003E).
// Reference: Matter Core Spec 1.5, Section 11.18.
//
// # Implementation status
//
// Certificates exchanged by this client (CertificateChainResponse's DAC/PAI,
// and the RCAC/NOC sent via AddTrustedRootCertificate/AddNOC) are converted
// to/from DER at the package boundary via matter/credentials/chipcert, so
// callers always work with plain X.509 DER, consistent with the rest of this
// codebase (matter/config, matter/protocol/case).
//
// Device attestation is verified pragmatically: only the DAC's own signature
// over AttestationElements/NOCSRElements is checked (see
// matter/credentials.VerifyAttestationSignature/VerifyNOCSRElementsSignature)
// — this package does not build or verify a DAC -> PAI -> PAA chain of trust
// against a Product Attestation Authority store, and does not validate the
// device's Certification Declaration. See matter/credentials's package doc
// for the reasoning; this is not suitable for production/certified
// commissioner use.
package operationalcredentials

import (
	"errors"
	"fmt"

	"github.com/cybergarage/go-matter/matter/credentials/chipcert"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
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

// NOCStatus values returned in a NOCResponse's StatusCode field.
// 11.18.5.6. NodeOperationalCertStatusEnum.
const nocStatusOK uint8 = 0

// ErrNotImplemented is returned by operations this package does not support
// (Thread-only flows and vendor-reserved fields are out of scope).
var ErrNotImplemented = errors.New("operationalcredentials: not yet implemented")

// AttestationRequest sends an AttestationRequest command to the device and
// returns the raw AttestationElements TLV bytes and the device's signature
// over them (verify with matter/credentials.VerifyAttestationSignature once
// the DAC public key is known, per commissioning_impl.go's sequencing).
// 11.18.7.1. AttestationRequest Command.
// Returns (attestationElementsTLV, signature, error).
func AttestationRequest(sess session.SecureSession, ep im.EndpointID, nonce []byte) ([]byte, []byte, error) {
	fields, err := buildAttestationRequestFields(nonce)
	if err != nil {
		return nil, nil, fmt.Errorf("operationalcredentials: build AttestationRequest fields: %w", err)
	}
	resp, err := im.Invoke(sess, ep, ClusterID, AttestationRequestCommandID, fields)
	if err != nil {
		return nil, nil, fmt.Errorf("operationalcredentials: AttestationRequest: %w", err)
	}
	if !resp.IsSuccess() {
		return nil, nil, invokeStatusError("AttestationRequest", resp)
	}
	elements, ok := fieldBytes(resp, 0)
	if !ok {
		return nil, nil, fmt.Errorf("operationalcredentials: AttestationResponse missing AttestationElements")
	}
	sig, ok := fieldBytes(resp, 1)
	if !ok {
		return nil, nil, fmt.Errorf("operationalcredentials: AttestationResponse missing AttestationSignature")
	}
	return elements, sig, nil
}

// CertificateChainRequest requests a certificate (DAC or PAI) from the
// device and returns it DER-encoded. Unlike the fabric's own operational
// certificates (NOC/ICAC/RCAC), which the device conveys using the compact
// Matter-TLV CHIPCert encoding, the manufacturer-provisioned DAC/PAI
// attestation certificates returned here are already plain DER — per
// connectedhomeip's DeviceAttestationCredentialsProvider interface
// (GetDeviceAttestationCert/GetProductAttestationIntermediateCert, whose
// callers use constants literally named e.g. kMaxDERCertLength) — so no
// chipcert.TLVToDER conversion applies to this response.
// certificateType: 1 = DAC, 2 = PAI.
// 11.18.7.3. CertificateChainRequest Command.
// Returns (certDER, error).
func CertificateChainRequest(sess session.SecureSession, ep im.EndpointID, certificateType uint8) ([]byte, error) {
	fields, err := buildCertificateChainRequestFields(certificateType)
	if err != nil {
		return nil, fmt.Errorf("operationalcredentials: build CertificateChainRequest fields: %w", err)
	}
	resp, err := im.Invoke(sess, ep, ClusterID, CertificateChainRequestCommandID, fields)
	if err != nil {
		return nil, fmt.Errorf("operationalcredentials: CertificateChainRequest: %w", err)
	}
	if !resp.IsSuccess() {
		return nil, invokeStatusError("CertificateChainRequest", resp)
	}
	certDER, ok := fieldBytes(resp, 0)
	if !ok {
		return nil, fmt.Errorf("operationalcredentials: CertificateChainResponse missing Certificate")
	}
	return certDER, nil
}

// CSRRequest requests a Certificate Signing Request from the device and
// returns the raw NOCSRElements TLV bytes and the device's signature over
// them (verify with matter/credentials.VerifyNOCSRElementsSignature).
// 11.18.7.5. CSRRequest Command.
// Returns (nocsrElementsTLV, signature, error).
func CSRRequest(sess session.SecureSession, ep im.EndpointID, csrNonce []byte) ([]byte, []byte, error) {
	fields, err := buildCSRRequestFields(csrNonce)
	if err != nil {
		return nil, nil, fmt.Errorf("operationalcredentials: build CSRRequest fields: %w", err)
	}
	resp, err := im.Invoke(sess, ep, ClusterID, CSRRequestCommandID, fields)
	if err != nil {
		return nil, nil, fmt.Errorf("operationalcredentials: CSRRequest: %w", err)
	}
	if !resp.IsSuccess() {
		return nil, nil, invokeStatusError("CSRRequest", resp)
	}
	elements, ok := fieldBytes(resp, 0)
	if !ok {
		return nil, nil, fmt.Errorf("operationalcredentials: CSRResponse missing NOCSRElements")
	}
	sig, ok := fieldBytes(resp, 1)
	if !ok {
		return nil, nil, fmt.Errorf("operationalcredentials: CSRResponse missing AttestationSignature")
	}
	return elements, sig, nil
}

// AddTrustedRootCertificate adds a trusted root certificate (the
// commissioner's RCAC, DER-encoded) to the device.
// 11.18.7.11. AddTrustedRootCertificate Command.
func AddTrustedRootCertificate(sess session.SecureSession, ep im.EndpointID, rootCertDER []byte) error {
	rootTLV, err := chipcert.DERToTLV(rootCertDER)
	if err != nil {
		return fmt.Errorf("operationalcredentials: encode root certificate: %w", err)
	}
	fields, err := buildAddTrustedRootCertificateFields(rootTLV)
	if err != nil {
		return fmt.Errorf("operationalcredentials: build AddTrustedRootCertificate fields: %w", err)
	}
	resp, err := im.Invoke(sess, ep, ClusterID, AddTrustedRootCertificateCommandID, fields)
	if err != nil {
		return fmt.Errorf("operationalcredentials: AddTrustedRootCertificate: %w", err)
	}
	if !resp.IsSuccess() {
		return invokeStatusError("AddTrustedRootCertificate", resp)
	}
	return nil
}

// AddNOC provisions the device with a Node Operational Certificate (and
// optional Intermediate CA Certificate, both DER-encoded), the fabric's
// Identity Protection Key, the CASE admin subject (the administrator's node
// ID) and the commissioner's vendor ID, completing fabric joining.
// 11.18.7.6. AddNOC Command.
func AddNOC(sess session.SecureSession, ep im.EndpointID, nocDER, icacDER, ipk []byte, caseAdminSubject uint64, adminVendorID uint16) error {
	nocTLV, err := chipcert.DERToTLV(nocDER)
	if err != nil {
		return fmt.Errorf("operationalcredentials: encode NOC: %w", err)
	}
	var icacTLV []byte
	if len(icacDER) != 0 {
		icacTLV, err = chipcert.DERToTLV(icacDER)
		if err != nil {
			return fmt.Errorf("operationalcredentials: encode ICAC: %w", err)
		}
	}
	fields, err := buildAddNOCFields(nocTLV, icacTLV, ipk, caseAdminSubject, adminVendorID)
	if err != nil {
		return fmt.Errorf("operationalcredentials: build AddNOC fields: %w", err)
	}
	resp, err := im.Invoke(sess, ep, ClusterID, AddNOCCommandID, fields)
	if err != nil {
		return fmt.Errorf("operationalcredentials: AddNOC: %w", err)
	}
	if !resp.IsSuccess() {
		return invokeStatusError("AddNOC", resp)
	}
	if status, ok := fieldUnsigned1(resp, 0); ok && status != nocStatusOK {
		debugText, _ := fieldUTF8(resp, 2)
		return fmt.Errorf("operationalcredentials: AddNOC failed: NOCResponse status=%d %s", status, debugText)
	}
	return nil
}

func buildAttestationRequestFields(nonce []byte) ([]byte, error) {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewContextTag(1))
	if err := enc.PutOctet(tlv.NewContextTag(0), nonce); err != nil {
		return nil, err
	}
	if err := enc.EndContainer(); err != nil {
		return nil, err
	}
	return enc.Bytes(), nil
}

func buildCertificateChainRequestFields(certificateType uint8) ([]byte, error) {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewContextTag(1))
	enc.PutUnsigned1(tlv.NewContextTag(0), certificateType)
	if err := enc.EndContainer(); err != nil {
		return nil, err
	}
	return enc.Bytes(), nil
}

func buildCSRRequestFields(csrNonce []byte) ([]byte, error) {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewContextTag(1))
	if err := enc.PutOctet(tlv.NewContextTag(0), csrNonce); err != nil {
		return nil, err
	}
	if err := enc.EndContainer(); err != nil {
		return nil, err
	}
	return enc.Bytes(), nil
}

func buildAddTrustedRootCertificateFields(rootCertTLV []byte) ([]byte, error) {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewContextTag(1))
	if err := enc.PutOctet(tlv.NewContextTag(0), rootCertTLV); err != nil {
		return nil, err
	}
	if err := enc.EndContainer(); err != nil {
		return nil, err
	}
	return enc.Bytes(), nil
}

func buildAddNOCFields(nocTLV, icacTLV, ipk []byte, caseAdminSubject uint64, adminVendorID uint16) ([]byte, error) {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewContextTag(1))
	if err := enc.PutOctet(tlv.NewContextTag(0), nocTLV); err != nil {
		return nil, err
	}
	if len(icacTLV) != 0 {
		if err := enc.PutOctet(tlv.NewContextTag(1), icacTLV); err != nil {
			return nil, err
		}
	}
	if err := enc.PutOctet(tlv.NewContextTag(2), ipk); err != nil {
		return nil, err
	}
	if err := enc.PutUnsigned(tlv.NewContextTag(3), caseAdminSubject); err != nil {
		return nil, err
	}
	enc.PutUnsigned2(tlv.NewContextTag(4), adminVendorID)
	if err := enc.EndContainer(); err != nil {
		return nil, err
	}
	return enc.Bytes(), nil
}

func fieldBytes(resp *im.InvokeResponse, tag uint8) ([]byte, bool) {
	elem, ok := resp.Field(tag)
	if !ok {
		return nil, false
	}
	return elem.Bytes()
}

func fieldUnsigned1(resp *im.InvokeResponse, tag uint8) (uint8, bool) {
	elem, ok := resp.Field(tag)
	if !ok {
		return 0, false
	}
	return elem.Unsigned1()
}

func fieldUTF8(resp *im.InvokeResponse, tag uint8) (string, bool) {
	elem, ok := resp.Field(tag)
	if !ok {
		return "", false
	}
	return elem.UTF8()
}

func invokeStatusError(command string, resp *im.InvokeResponse) error {
	return fmt.Errorf("operationalcredentials: %s failed: IM status 0x%02X, cluster status 0x%02X",
		command, resp.Status.IMStatus, resp.Status.ClusterStatus)
}
