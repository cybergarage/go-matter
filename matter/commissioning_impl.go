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

package matter

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter/cluster/generalcommissioning"
	"github.com/cybergarage/go-matter/matter/cluster/networkcommissioning"
	"github.com/cybergarage/go-matter/matter/cluster/operationalcredentials"
	"github.com/cybergarage/go-matter/matter/protocol/session"
)

// defaultEndpointID is the Root Endpoint used for commissioning cluster commands.
// 9.5. Endpoints.
const defaultEndpointID = 0

const (
	// 11.18.7.1. AttestationRequest Command (AttestationNonce is 32 bytes).
	attestationNonceLength = 32
	// 11.18.7.5. CSRRequest Command (CSRNonce is 32 bytes).
	csrNonceLength = 32

	// 11.18.5.7. CertificateChainTypeEnum (DAC = 1, PAI = 2).
	certificateTypeDAC uint8 = 1
	certificateTypePAI uint8 = 2

	// 11.8.7.3 / 11.8.7.7. Optional breadcrumb field for Network Commissioning commands.
	networkCommissioningBreadcrumb uint64 = 0
)

type operationalCredentialInputs struct {
	rootCertificate []byte // RCAC: Root Certificate Authority Certificate.
	noc             []byte // NOC: Node Operational Certificate.
	icac            []byte // ICAC: Intermediate CA Certificate.
	ipk             []byte // IPK: Identity Protection Key.
	caseAdminNodeID uint64 // CASE Admin Node ID.
	adminVendorID   uint16 // Admin Vendor ID.
}

type networkCommissioningInputs struct {
	ssid []byte // SSID: Service Set Identifier for Wi-Fi network.
	// credentials is Wi-Fi authentication data (passphrase or PSK).
	credentials []byte
}

// commissionWithSession executes the post-PASE commissioning flow over the given SecureSession.
// The flow follows the Matter Core Spec commissioning procedure (section 5.5):
//
//  1. ArmFailSafe – arms the commissioning fail-safe timer (General Commissioning cluster 0x0030)
//  2. Device Attestation – AttestationRequest, CertificateChainRequest, CSRRequest (TODO)
//  3. Operational Credentials – AddTrustedRootCertificate, AddNOC (TODO)
//  4. Network Commissioning – AddOrUpdateWiFiNetwork / ConnectNetwork (TODO, BLE-specific)
//  5. CommissioningComplete – releases the fail-safe and completes commissioning
//
// 5.5. Commissioning Flows.
func commissionWithSession(sess session.SecureSession) error {
	const (
		armFailSafeExpiry uint16 = 60 // seconds
		breadcrumb        uint64 = 1
	)

	// Step 1: ArmFailSafe
	// 11.9.7.1. ArmFailSafe Command.
	log.Infof("Commissioning: ArmFailSafe (expiry=%ds, breadcrumb=%d)", armFailSafeExpiry, breadcrumb)
	if err := generalcommissioning.ArmFailSafe(sess, defaultEndpointID, armFailSafeExpiry, breadcrumb); err != nil {
		return err
	}

	// Step 2: Device Attestation
	// 11.18.7.1. AttestationRequest Command.
	log.Infof("Commissioning: Device Attestation")
	if err := commissionDeviceAttestation(sess); err != nil {
		return err
	}

	// Step 3: Operational Credentials
	// 11.18.7.6. AddNOC Command.
	log.Infof("Commissioning: Operational Credentials")
	if err := commissionOperationalCredentials(sess, loadOperationalCredentialInputs()); err != nil {
		return err
	}

	// Step 4: Network Commissioning
	// 11.8.7.3. AddOrUpdateWiFiNetwork Command.
	log.Infof("Commissioning: Network Commissioning")
	if err := commissionNetwork(sess, loadNetworkCommissioningInputs()); err != nil {
		return err
	}

	// Step 5: CommissioningComplete
	// 11.9.7.7. CommissioningComplete Command.
	log.Infof("Commissioning: CommissioningComplete")
	if err := generalcommissioning.CommissioningComplete(sess, defaultEndpointID); err != nil {
		return err
	}

	log.Infof("Commissioning: complete")
	return nil
}

func commissionDeviceAttestation(sess session.SecureSession) error {
	attestationNonce := make([]byte, attestationNonceLength)
	if _, err := rand.Read(attestationNonce); err != nil {
		return fmt.Errorf("commissioning: generate attestation nonce: %w", err)
	}
	if _, err := operationalcredentials.AttestationRequest(sess, defaultEndpointID, attestationNonce); err != nil {
		if errors.Is(err, operationalcredentials.ErrNotImplemented) {
			log.Infof("Commissioning: Device Attestation skipped: %v", err)
			return nil
		}
		return fmt.Errorf("commissioning: AttestationRequest: %w", err)
	}

	if _, err := operationalcredentials.CertificateChainRequest(sess, defaultEndpointID, certificateTypeDAC); err != nil {
		if errors.Is(err, operationalcredentials.ErrNotImplemented) {
			log.Infof("Commissioning: DAC request skipped: %v", err)
			return nil
		}
		return fmt.Errorf("commissioning: CertificateChainRequest(DAC): %w", err)
	}

	if _, err := operationalcredentials.CertificateChainRequest(sess, defaultEndpointID, certificateTypePAI); err != nil {
		if errors.Is(err, operationalcredentials.ErrNotImplemented) {
			log.Infof("Commissioning: PAI request skipped: %v", err)
			return nil
		}
		return fmt.Errorf("commissioning: CertificateChainRequest(PAI): %w", err)
	}

	csrNonce := make([]byte, csrNonceLength)
	if _, err := rand.Read(csrNonce); err != nil {
		return fmt.Errorf("commissioning: generate CSR nonce: %w", err)
	}
	if _, err := operationalcredentials.CSRRequest(sess, defaultEndpointID, csrNonce); err != nil {
		if errors.Is(err, operationalcredentials.ErrNotImplemented) {
			log.Infof("Commissioning: CSR request skipped: %v", err)
			return nil
		}
		return fmt.Errorf("commissioning: CSRRequest: %w", err)
	}

	return nil
}

func commissionOperationalCredentials(sess session.SecureSession, inputs operationalCredentialInputs) error {
	if len(inputs.rootCertificate) == 0 || len(inputs.noc) == 0 || len(inputs.ipk) == 0 {
		log.Infof("Commissioning: Operational Credentials skipped: missing RCAC/NOC/IPK provisioning inputs")
		return nil
	}

	if err := operationalcredentials.AddTrustedRootCertificate(sess, defaultEndpointID, inputs.rootCertificate); err != nil {
		if errors.Is(err, operationalcredentials.ErrNotImplemented) {
			log.Infof("Commissioning: AddTrustedRootCertificate skipped: %v", err)
			return nil
		}
		return fmt.Errorf("commissioning: AddTrustedRootCertificate: %w", err)
	}

	if err := operationalcredentials.AddNOC(
		sess,
		defaultEndpointID,
		inputs.noc,
		inputs.icac,
		inputs.ipk,
		inputs.caseAdminNodeID,
		inputs.adminVendorID,
	); err != nil {
		if errors.Is(err, operationalcredentials.ErrNotImplemented) {
			log.Infof("Commissioning: AddNOC skipped: %v", err)
			return nil
		}
		return fmt.Errorf("commissioning: AddNOC: %w", err)
	}

	return nil
}

func commissionNetwork(sess session.SecureSession, inputs networkCommissioningInputs) error {
	if len(inputs.ssid) == 0 || len(inputs.credentials) == 0 {
		log.Infof("Commissioning: Network Commissioning skipped: missing Wi-Fi SSID/credentials")
		return nil
	}

	if err := networkcommissioning.AddOrUpdateWiFiNetwork(
		sess,
		defaultEndpointID,
		inputs.ssid,
		inputs.credentials,
		networkCommissioningBreadcrumb,
	); err != nil {
		if errors.Is(err, networkcommissioning.ErrNotImplemented) {
			log.Infof("Commissioning: AddOrUpdateWiFiNetwork skipped: %v", err)
			return nil
		}
		return fmt.Errorf("commissioning: AddOrUpdateWiFiNetwork: %w", err)
	}

	if err := networkcommissioning.ConnectNetwork(sess, defaultEndpointID, inputs.ssid, networkCommissioningBreadcrumb); err != nil {
		if errors.Is(err, networkcommissioning.ErrNotImplemented) {
			log.Infof("Commissioning: ConnectNetwork skipped: %v", err)
			return nil
		}
		return fmt.Errorf("commissioning: ConnectNetwork: %w", err)
	}

	return nil
}

func loadOperationalCredentialInputs() operationalCredentialInputs {
	// TODO: Wire this from commissioner/device provisioning inputs once PKI material is supported.
	return operationalCredentialInputs{}
}

func loadNetworkCommissioningInputs() networkCommissioningInputs {
	// TODO: Wire this from commissioning options (e.g., pairing code-wifi SSID/password inputs).
	return networkCommissioningInputs{}
}
