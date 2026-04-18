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
	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter/cluster/generalcommissioning"
	"github.com/cybergarage/go-matter/matter/protocol/session"
)

// defaultEndpointID is the Root Endpoint used for commissioning cluster commands.
// 9.5. Endpoints.
const defaultEndpointID = 0

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
	// 11.10.7.2. ArmFailSafe Command.
	log.Infof("Commissioning: ArmFailSafe (expiry=%ds, breadcrumb=%d)", armFailSafeExpiry, breadcrumb)
	if err := generalcommissioning.ArmFailSafe(sess, defaultEndpointID, armFailSafeExpiry, breadcrumb); err != nil {
		return err
	}

	// Step 2: Device Attestation (not yet implemented — requires Matter PKI infrastructure)
	// TODO: Call operationalcredentials.AttestationRequest, CertificateChainRequest, CSRRequest.
	// 11.18.6.1. AttestationRequest Command.
	log.Infof("Commissioning: Device Attestation (TODO: not yet implemented)")

	// Step 3: Operational Credentials (not yet implemented — requires Matter PKI infrastructure)
	// TODO: Call operationalcredentials.AddTrustedRootCertificate, AddNOC.
	// 11.18.6.8. AddNOC Command.
	log.Infof("Commissioning: Operational Credentials (TODO: not yet implemented)")

	// Step 4: Network Commissioning (not yet implemented — required for BLE-commissioned devices)
	// TODO: Call networkcommissioning.AddOrUpdateWiFiNetwork, ConnectNetwork.
	// 11.9.7.3. AddOrUpdateWiFiNetwork Command.
	log.Infof("Commissioning: Network Commissioning (TODO: not yet implemented)")

	// Step 5: CommissioningComplete
	// 11.10.7.6. CommissioningComplete Command.
	log.Infof("Commissioning: CommissioningComplete")
	if err := generalcommissioning.CommissioningComplete(sess, defaultEndpointID); err != nil {
		return err
	}

	log.Infof("Commissioning: complete")
	return nil
}
