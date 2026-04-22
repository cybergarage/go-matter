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
	"context"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter/cluster/generalcommissioning"
	"github.com/cybergarage/go-matter/matter/cluster/networkcommissioning"
	"github.com/cybergarage/go-matter/matter/cluster/operationalcredentials"
	"github.com/cybergarage/go-matter/matter/config"
	mdnspkg "github.com/cybergarage/go-matter/matter/mdns"
	caseprotocol "github.com/cybergarage/go-matter/matter/protocol/case"
	"github.com/cybergarage/go-matter/matter/protocol/im"
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

var (
	armFailSafeCommand                    = generalcommissioning.ArmFailSafe
	commissioningCompleteCommand          = generalcommissioning.CommissioningComplete
	addTrustedRootCertificateCommand      = operationalcredentials.AddTrustedRootCertificate
	addNOCCommand                         = operationalcredentials.AddNOC
	addOrUpdateWiFiNetworkCommand         = networkcommissioning.AddOrUpdateWiFiNetwork
	connectNetworkCommand                 = networkcommissioning.ConnectNetwork
	supportsConcurrentConnectionAttribute = readSupportsConcurrentConnection
	operationalNodeDiscoverer             = discoverOperationalNode
	establishOperationalCASESession       = establishCASESession
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
//  2. Device Attestation – AttestationRequest, CertificateChainRequest, CSRRequest
//  3. Operational Credentials – AddTrustedRootCertificate, AddNOC
//  4. Network Commissioning – AddOrUpdateWiFiNetwork / ConnectNetwork (when the device requires operational-network provisioning)
//  5. CommissioningComplete – releases the fail-safe and completes commissioning
//
// 5.5. Commissioning Flows.
func commissionWithSession(
	ctx context.Context,
	sess session.SecureSession,
	discoverer mdnspkg.Discoverer,
	operationalCfg config.OperationalCredentialsConfig,
	wifiCfg config.WiFiNetworkConfig,
	adminCfg config.AdministratorConfig,
	requireNetwork bool,
) error {
	concurrent, err := supportsConcurrentConnectionAttribute(sess)
	if err != nil {
		return fmt.Errorf("commissioning: determine concurrent-connection capability: %w", err)
	}
	if !concurrent {
		return fmt.Errorf("commissioning: non-concurrent commissioning not yet supported")
	}

	if err := commissionOverPASE(sess, operationalCfg, wifiCfg, requireNetwork); err != nil {
		return err
	}

	if err := finalizeCommissioningOverCASE(ctx, discoverer, adminCfg); err != nil {
		return err
	}

	log.Infof("Commissioning: complete")
	return nil
}

func commissionOverPASE(
	sess session.SecureSession,
	operationalCfg config.OperationalCredentialsConfig,
	wifiCfg config.WiFiNetworkConfig,
	requireNetwork bool,
) error {
	const (
		armFailSafeExpiry uint16 = 60 // seconds
		breadcrumb        uint64 = 1
	)

	// Step 1: ArmFailSafe
	// 11.10.7.2. ArmFailSafe Command.
	log.Infof("Commissioning: ArmFailSafe (expiry=%ds, breadcrumb=%d)", armFailSafeExpiry, breadcrumb)
	if err := armFailSafeCommand(sess, defaultEndpointID, armFailSafeExpiry, breadcrumb); err != nil {
		return err
	}

	// Step 2: Device Attestation
	// 11.18.7.1. AttestationRequest Command.
	log.Infof("Commissioning: Device Attestation")
	if err := commissionDeviceAttestation(sess); err != nil {
		return err
	}

	// Step 3: Operational Credentials
	// Matter 1.2 Core Spec 5.5 "Commissioning Flows", step 9:
	// Commissioner SHALL install operational credentials using AddTrustedRootCertificate and AddNOC.
	log.Infof("Commissioning: Operational Credentials")
	if err := commissionOperationalCredentials(sess, operationalCfg); err != nil {
		return err
	}

	// Step 4: Network Commissioning
	// Matter 1.2 Core Spec 5.5 "Commissioning Flows", steps 12-13:
	// configure the operational network only if the Commissionee supports it and requires it,
	// then invoke ConnectNetwork unless the Commissionee is already on the desired operational network.
	log.Infof("Commissioning: Network Commissioning")
	if err := commissionNetwork(sess, wifiCfg, requireNetwork); err != nil {
		return err
	}

	return nil
}

func finalizeCommissioningOverCASE(
	ctx context.Context,
	discoverer mdnspkg.Discoverer,
	adminCfg config.AdministratorConfig,
) error {
	if adminCfg == nil {
		return fmt.Errorf("commissioning: administrator config is required for CASE finalization")
	}
	if discoverer == nil {
		return fmt.Errorf("commissioning: discoverer is required for operational discovery")
	}

	log.Infof("Commissioning: Operational Discovery")
	node, err := operationalNodeDiscoverer(ctx, discoverer, adminCfg)
	if err != nil {
		return err
	}

	log.Infof("Commissioning: CASE")
	caseSess, err := establishOperationalCASESession(ctx, node, adminCfg)
	if err != nil {
		return err
	}

	log.Infof("Commissioning: CommissioningComplete")
	if err := commissioningCompleteCommand(caseSess, defaultEndpointID); err != nil {
		return err
	}

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

func commissionOperationalCredentials(sess session.SecureSession, cfg config.OperationalCredentialsConfig) error {
	if cfg == nil {
		return fmt.Errorf("commissioning: operational credentials config is required")
	}

	inputs, err := loadOperationalCredentialInputs(cfg)
	if err != nil {
		return err
	}

	if err := addTrustedRootCertificateCommand(sess, defaultEndpointID, inputs.rootCertificate); err != nil {
		if errors.Is(err, operationalcredentials.ErrNotImplemented) {
			log.Infof("Commissioning: AddTrustedRootCertificate skipped: %v", err)
			return nil
		}
		return fmt.Errorf("commissioning: AddTrustedRootCertificate: %w", err)
	}

	if err := addNOCCommand(
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

func commissionNetwork(sess session.SecureSession, cfg config.WiFiNetworkConfig, requireNetwork bool) error {
	if cfg == nil {
		if requireNetwork {
			return fmt.Errorf("commissioning: Wi-Fi network config is required for this commissioning flow")
		}
		log.Infof("Commissioning: Network Commissioning skipped: device is assumed to already be on the desired operational network")
		return nil
	}

	inputs, err := loadNetworkCommissioningInputs(cfg)
	if err != nil {
		return err
	}

	if err := addOrUpdateWiFiNetworkCommand(
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

	if err := connectNetworkCommand(sess, defaultEndpointID, inputs.ssid, networkCommissioningBreadcrumb); err != nil {
		if errors.Is(err, networkcommissioning.ErrNotImplemented) {
			log.Infof("Commissioning: ConnectNetwork skipped: %v", err)
			return nil
		}
		return fmt.Errorf("commissioning: ConnectNetwork: %w", err)
	}

	return nil
}

func readSupportsConcurrentConnection(sess session.SecureSession) (bool, error) {
	return im.ReadBoolAttribute(
		sess,
		defaultEndpointID,
		generalcommissioning.ClusterID,
		generalcommissioning.SupportsConcurrentConnectionAttributeID,
	)
}

func discoverOperationalNode(
	ctx context.Context,
	discoverer mdnspkg.Discoverer,
	_ config.AdministratorConfig,
) (mdnspkg.CommissionableNode, error) {
	nodes, err := discoverer.Search(ctx, mdnspkg.NewOperationalNodeQuery(""))
	if err != nil {
		return nil, fmt.Errorf("commissioning: operational discovery failed: %w", err)
	}
	if len(nodes) == 0 {
		return nil, fmt.Errorf("commissioning: operational discovery timeout: no operational node found")
	}
	return nodes[0], nil
}

func establishCASESession(
	ctx context.Context,
	_ mdnspkg.CommissionableNode,
	adminCfg config.AdministratorConfig,
) (session.SecureSession, error) {
	initiator := caseprotocol.NewInitiator(noopTransport{}, adminCfg)
	_, err := initiator.EstablishSession(ctx)
	if err != nil {
		return nil, fmt.Errorf("commissioning: CASE finalization: %w", err)
	}
	return nil, fmt.Errorf("commissioning: CASE finalization: missing secure session result")
}

type noopTransport struct{}

func (noopTransport) Transmit(context.Context, []byte) error  { return nil }
func (noopTransport) Receive(context.Context) ([]byte, error) { return nil, nil }

func loadOperationalCredentialInputs(cfg config.OperationalCredentialsConfig) (operationalCredentialInputs, error) {
	rootCert, _ := cfg.RootCertificate()
	noc, _ := cfg.NOC()
	icac, _ := cfg.ICAC()
	ipk, _ := cfg.IPK()
	caseAdminNodeID, _ := cfg.CASEAdminNodeID()
	adminVendorID, _ := cfg.AdminVendorID()
	if len(rootCert) == 0 {
		return operationalCredentialInputs{}, fmt.Errorf("commissioning: operational credentials config missing root certificate")
	}
	if len(noc) == 0 {
		return operationalCredentialInputs{}, fmt.Errorf("commissioning: operational credentials config missing NOC")
	}
	if len(ipk) == 0 {
		return operationalCredentialInputs{}, fmt.Errorf("commissioning: operational credentials config missing IPK")
	}
	if caseAdminNodeID == 0 {
		return operationalCredentialInputs{}, fmt.Errorf("commissioning: operational credentials config missing CASE admin node ID")
	}
	if adminVendorID == 0 {
		return operationalCredentialInputs{}, fmt.Errorf("commissioning: operational credentials config missing admin vendor ID")
	}
	return operationalCredentialInputs{
		rootCertificate: rootCert,
		noc:             noc,
		icac:            icac,
		ipk:             ipk,
		caseAdminNodeID: caseAdminNodeID,
		adminVendorID:   adminVendorID,
	}, nil
}

func loadNetworkCommissioningInputs(cfg config.WiFiNetworkConfig) (networkCommissioningInputs, error) {
	ssid, _ := cfg.SSID()
	credentials, _ := cfg.Credentials()
	if len(ssid) == 0 {
		return networkCommissioningInputs{}, fmt.Errorf("commissioning: Wi-Fi network config missing SSID")
	}
	if len(credentials) == 0 {
		return networkCommissioningInputs{}, fmt.Errorf("commissioning: Wi-Fi network config missing credentials")
	}
	return networkCommissioningInputs{
		ssid:        ssid,
		credentials: credentials,
	}, nil
}
