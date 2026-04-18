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
	attestationNonceLength = 32
	csrNonceLength         = 32

	certificateTypeDAC uint8 = 1
	certificateTypePAI uint8 = 2
)

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
	if err := commissionOperationalCredentials(sess); err != nil {
		return err
	}

	// Step 4: Network Commissioning
	// 11.8.7.3. AddOrUpdateWiFiNetwork Command.
	log.Infof("Commissioning: Network Commissioning")
	if err := commissionNetwork(sess); err != nil {
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

func commissionOperationalCredentials(sess session.SecureSession) error {
	// Root CA / NOC material is not available yet in the current commissioning inputs.
	rootCertificate := []byte(nil)
	noc := []byte(nil)
	icac := []byte(nil)
	ipk := []byte(nil)
	caseAdminSubject := uint64(0)
	adminVendorID := uint16(0)
	if rootCertificate == nil || noc == nil || ipk == nil {
		log.Infof("Commissioning: Operational Credentials skipped: missing RCAC/NOC/IPK provisioning inputs")
		return nil
	}

	if err := operationalcredentials.AddTrustedRootCertificate(sess, defaultEndpointID, rootCertificate); err != nil {
		if errors.Is(err, operationalcredentials.ErrNotImplemented) {
			log.Infof("Commissioning: AddTrustedRootCertificate skipped: %v", err)
			return nil
		}
		return fmt.Errorf("commissioning: AddTrustedRootCertificate: %w", err)
	}

	if err := operationalcredentials.AddNOC(sess, defaultEndpointID, noc, icac, ipk, caseAdminSubject, adminVendorID); err != nil {
		if errors.Is(err, operationalcredentials.ErrNotImplemented) {
			log.Infof("Commissioning: AddNOC skipped: %v", err)
			return nil
		}
		return fmt.Errorf("commissioning: AddNOC: %w", err)
	}

	return nil
}

func commissionNetwork(sess session.SecureSession) error {
	// Wi-Fi network credentials are not available yet in the current commissioning inputs.
	ssid := []byte(nil)
	credentials := []byte(nil)
	if ssid == nil || credentials == nil {
		log.Infof("Commissioning: Network Commissioning skipped: missing Wi-Fi SSID/credentials")
		return nil
	}

	if err := networkcommissioning.AddOrUpdateWiFiNetwork(sess, defaultEndpointID, ssid, credentials, 0); err != nil {
		if errors.Is(err, networkcommissioning.ErrNotImplemented) {
			log.Infof("Commissioning: AddOrUpdateWiFiNetwork skipped: %v", err)
			return nil
		}
		return fmt.Errorf("commissioning: AddOrUpdateWiFiNetwork: %w", err)
	}

	if err := networkcommissioning.ConnectNetwork(sess, defaultEndpointID, ssid, 0); err != nil {
		if errors.Is(err, networkcommissioning.ErrNotImplemented) {
			log.Infof("Commissioning: ConnectNetwork skipped: %v", err)
			return nil
		}
		return fmt.Errorf("commissioning: ConnectNetwork: %w", err)
	}

	return nil
}
