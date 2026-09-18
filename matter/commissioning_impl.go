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
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter/cluster/generalcommissioning"
	"github.com/cybergarage/go-matter/matter/cluster/networkcommissioning"
	"github.com/cybergarage/go-matter/matter/cluster/operationalcredentials"
	"github.com/cybergarage/go-matter/matter/config"
	"github.com/cybergarage/go-matter/matter/credentials"
	mdnspkg "github.com/cybergarage/go-matter/matter/mdns"
	caseprotocol "github.com/cybergarage/go-matter/matter/protocol/case"
	"github.com/cybergarage/go-matter/matter/protocol/im"
	"github.com/cybergarage/go-matter/matter/protocol/session"
	"github.com/cybergarage/go-matter/matter/types"
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
	attestationRequestCommand             = operationalcredentials.AttestationRequest
	certificateChainRequestCommand        = operationalcredentials.CertificateChainRequest
	csrRequestCommand                     = operationalcredentials.CSRRequest
	addTrustedRootCertificateCommand      = operationalcredentials.AddTrustedRootCertificate
	addNOCCommand                         = operationalcredentials.AddNOC
	addOrUpdateWiFiNetworkCommand         = networkcommissioning.AddOrUpdateWiFiNetwork
	connectNetworkCommand                 = networkcommissioning.ConnectNetwork
	supportsConcurrentConnectionAttribute = readSupportsConcurrentConnection
	operationalNodeDiscoverer             = discoverOperationalNode
	establishOperationalCASESession       = establishCASESession
	// commissionDeviceAttestationFn allows the whole device-attestation phase
	// to be stubbed in tests that only care about sequencing around it.
	commissionDeviceAttestationFn = commissionDeviceAttestation
)

type networkCommissioningInputs struct {
	ssid []byte // SSID: Service Set Identifier for Wi-Fi network.
	// credentials is Wi-Fi authentication data (passphrase or PSK).
	credentials []byte
}

// deviceAttestationResult holds what commissionDeviceAttestation learns about
// the commissionee: the DAC public key (used to verify AttestationResponse
// and CSRResponse signatures) and the parsed CSR (used to issue its NOC).
type deviceAttestationResult struct {
	dacPubKey *ecdsa.PublicKey
	csr       *x509.CertificateRequest
}

// deviceOperationalIdentity is what commissionOperationalCredentials learns
// once it has issued and installed the device's NOC: the node ID it
// assigned, and the NOC/ICAC now installed on the device, used to locate and
// authenticate the device over CASE in finalizeCommissioningOverCASE.
type deviceOperationalIdentity struct {
	nodeID uint64
	noc    []byte // DER
	icac   []byte // DER, nil for this minimal CA (no intermediate).
}

// commissionWithSession executes the post-PASE commissioning flow over the given SecureSession.
// The flow follows the Matter Core Spec commissioning procedure (section 5.5):
//
//  1. ArmFailSafe – arms the commissioning fail-safe timer (General Commissioning cluster 0x0030)
//  2. Device Attestation – AttestationRequest, CertificateChainRequest, CSRRequest
//  3. Operational Credentials – issue a NOC from the device's CSR, AddTrustedRootCertificate, AddNOC
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

	identity, err := commissionOverPASE(sess, operationalCfg, adminCfg, wifiCfg, requireNetwork)
	if err != nil {
		return err
	}

	// sess.Transport() is passed through so finalizeCommissioningOverCASE can
	// try to reuse this same already-open connection for CASE instead of
	// opening a new one — see establishCASESession's doc comment for why.
	if err := finalizeCommissioningOverCASE(ctx, discoverer, operationalCfg, adminCfg, identity, sess.Transport()); err != nil {
		return err
	}

	log.Infof("Commissioning: complete")
	return nil
}

func commissionOverPASE(
	sess session.SecureSession,
	operationalCfg config.OperationalCredentialsConfig,
	adminCfg config.AdministratorConfig,
	wifiCfg config.WiFiNetworkConfig,
	requireNetwork bool,
) (deviceOperationalIdentity, error) {
	const (
		// armFailSafeExpiry must comfortably cover the entire commissioning
		// exchange, not just the PASE-side steps: on a real device, AddNOC
		// makes the device join the fabric and start re-advertising itself
		// operationally over mDNS, and CASE then has to rediscover it via
		// that new operational mDNS record before Sigma1 can even be sent —
		// on a busy network with many other mDNS-chatty devices, that
		// discovery step alone was observed taking ~55s, blowing well past
		// a 60s failsafe (armed once at the start, matching
		// DefaultCommissioningTimeout in commissioner.go) before Sigma1 was
		// ever transmitted.
		armFailSafeExpiry uint16 = 120 // seconds
		breadcrumb        uint64 = 1
	)

	// Step 1: ArmFailSafe
	// 11.10.7.2. ArmFailSafe Command.
	log.Infof("Commissioning: ArmFailSafe (expiry=%ds, breadcrumb=%d)", armFailSafeExpiry, breadcrumb)
	if err := armFailSafeCommand(sess, defaultEndpointID, armFailSafeExpiry, breadcrumb); err != nil {
		return deviceOperationalIdentity{}, err
	}

	// Step 2: Device Attestation
	// 11.18.7.1. AttestationRequest Command.
	log.Infof("Commissioning: Device Attestation")
	attResult, err := commissionDeviceAttestationFn(sess)
	if err != nil {
		return deviceOperationalIdentity{}, err
	}

	// Step 3: Operational Credentials
	// Matter 1.2 Core Spec 5.5 "Commissioning Flows", step 9:
	// Commissioner SHALL install operational credentials using AddTrustedRootCertificate and AddNOC.
	log.Infof("Commissioning: Operational Credentials")
	identity, err := commissionOperationalCredentials(sess, operationalCfg, adminCfg, attResult)
	if err != nil {
		return deviceOperationalIdentity{}, err
	}

	// Step 4: Network Commissioning
	// Matter 1.2 Core Spec 5.5 "Commissioning Flows", steps 12-13:
	// configure the operational network only if the Commissionee supports it and requires it,
	// then invoke ConnectNetwork unless the Commissionee is already on the desired operational network.
	log.Infof("Commissioning: Network Commissioning")
	if err := commissionNetwork(sess, wifiCfg, requireNetwork); err != nil {
		return deviceOperationalIdentity{}, err
	}

	return identity, nil
}

func finalizeCommissioningOverCASE(
	ctx context.Context,
	discoverer mdnspkg.Discoverer,
	operationalCfg config.OperationalCredentialsConfig,
	adminCfg config.AdministratorConfig,
	identity deviceOperationalIdentity,
	paseTransport caseprotocol.Transport,
) error {
	if adminCfg == nil {
		return fmt.Errorf("commissioning: administrator config is required for CASE finalization")
	}
	if discoverer == nil {
		return fmt.Errorf("commissioning: discoverer is required for operational discovery")
	}
	if operationalCfg == nil {
		return fmt.Errorf("commissioning: operational credentials config is required for CASE finalization")
	}

	peer, err := loadOperationalCASEPeer(operationalCfg, adminCfg, identity)
	if err != nil {
		return err
	}
	log.Infof(
		"Commissioning: Operational Discovery target service=%s peer_node_id=0x%016X ipk=%dB",
		peer.serviceInstance,
		peer.nodeID,
		len(peer.ipk),
	)

	log.Infof("Commissioning: Operational Discovery")
	node, err := operationalNodeDiscoverer(ctx, discoverer, peer)
	if err != nil {
		return err
	}

	log.Infof("Commissioning: CASE")
	caseSess, err := establishOperationalCASESession(ctx, node, peer, adminCfg, paseTransport)
	if err != nil {
		return err
	}
	if closer, ok := caseSess.Transport().(interface{ Close() error }); ok {
		defer func() {
			if err := closer.Close(); err != nil {
				log.Error(err)
			}
		}()
	}

	log.Infof("Commissioning: CommissioningComplete")
	if err := commissioningCompleteCommand(caseSess, defaultEndpointID); err != nil {
		return err
	}

	return nil
}

// commissionDeviceAttestation runs the AttestationRequest / CertificateChainRequest
// (DAC, PAI) / CSRRequest exchange and returns the device's DAC public key and
// parsed CSR. It verifies the DAC's signature over the AttestationResponse and
// CSRResponse payloads (see matter/credentials), but — per this codebase's
// documented, intentionally pragmatic scope — does not validate a DAC -> PAI
// -> PAA chain of trust, and does not verify the Certification Declaration.
func commissionDeviceAttestation(sess session.SecureSession) (deviceAttestationResult, error) {
	challenge := sess.SessionKeys().AttestationChallenge()
	if len(challenge) == 0 {
		return deviceAttestationResult{}, fmt.Errorf("commissioning: session has no attestation challenge")
	}

	attestationNonce := make([]byte, attestationNonceLength)
	if _, err := rand.Read(attestationNonce); err != nil {
		return deviceAttestationResult{}, fmt.Errorf("commissioning: generate attestation nonce: %w", err)
	}
	attestationElementsTLV, attestationSig, err := attestationRequestCommand(sess, defaultEndpointID, attestationNonce)
	if err != nil {
		return deviceAttestationResult{}, fmt.Errorf("commissioning: AttestationRequest: %w", err)
	}

	dacDER, err := certificateChainRequestCommand(sess, defaultEndpointID, certificateTypeDAC)
	if err != nil {
		return deviceAttestationResult{}, fmt.Errorf("commissioning: CertificateChainRequest(DAC): %w", err)
	}
	dacCert, err := x509.ParseCertificate(dacDER)
	if err != nil {
		return deviceAttestationResult{}, fmt.Errorf("commissioning: parse DAC: %w", err)
	}
	dacPubKey, ok := dacCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return deviceAttestationResult{}, fmt.Errorf("commissioning: DAC public key is not ECDSA")
	}

	if err := credentials.VerifyAttestationSignature(attestationElementsTLV, challenge, attestationSig, dacPubKey); err != nil {
		return deviceAttestationResult{}, fmt.Errorf("commissioning: %w", err)
	}
	if _, err := credentials.ParseAttestationElements(attestationElementsTLV); err != nil {
		return deviceAttestationResult{}, fmt.Errorf("commissioning: %w", err)
	}

	// PAI is fetched for completeness but its chain of trust to a Product
	// Attestation Authority is intentionally not validated — see the package
	// doc comment on matter/credentials and matter/cluster/operationalcredentials.
	if _, err := certificateChainRequestCommand(sess, defaultEndpointID, certificateTypePAI); err != nil {
		return deviceAttestationResult{}, fmt.Errorf("commissioning: CertificateChainRequest(PAI): %w", err)
	}
	log.Infof("Commissioning: PAI fetched; chain-of-trust validation intentionally skipped (see matter/credentials doc)")

	csrNonce := make([]byte, csrNonceLength)
	if _, err := rand.Read(csrNonce); err != nil {
		return deviceAttestationResult{}, fmt.Errorf("commissioning: generate CSR nonce: %w", err)
	}
	nocsrElementsTLV, csrSig, err := csrRequestCommand(sess, defaultEndpointID, csrNonce)
	if err != nil {
		return deviceAttestationResult{}, fmt.Errorf("commissioning: CSRRequest: %w", err)
	}
	if err := credentials.VerifyNOCSRElementsSignature(nocsrElementsTLV, challenge, csrSig, dacPubKey); err != nil {
		return deviceAttestationResult{}, fmt.Errorf("commissioning: %w", err)
	}
	elements, err := credentials.ParseNOCSRElements(nocsrElementsTLV)
	if err != nil {
		return deviceAttestationResult{}, fmt.Errorf("commissioning: %w", err)
	}
	csr, err := credentials.ParseCSR(elements.CSR)
	if err != nil {
		return deviceAttestationResult{}, fmt.Errorf("commissioning: %w", err)
	}

	return deviceAttestationResult{dacPubKey: dacPubKey, csr: csr}, nil
}

// loadCertificateAuthority builds the commissioner's certificate authority
// from the administrator's own root certificate and private key.
func loadCertificateAuthority(adminCfg config.AdministratorConfig) (*credentials.CertificateAuthority, error) {
	if adminCfg == nil {
		return nil, fmt.Errorf("commissioning: administrator config is required")
	}
	rootCert, _ := adminCfg.RootCertificate()
	rootKey, _ := adminCfg.RootPrivateKey()
	fabricID, _ := adminCfg.FabricID()
	ca, err := credentials.NewCertificateAuthority(rootCert, rootKey, fabricID)
	if err != nil {
		return nil, fmt.Errorf("commissioning: certificate authority: %w", err)
	}
	return ca, nil
}

func commissionOperationalCredentials(
	sess session.SecureSession,
	cfg config.OperationalCredentialsConfig,
	adminCfg config.AdministratorConfig,
	attResult deviceAttestationResult,
) (deviceOperationalIdentity, error) {
	if cfg == nil {
		return deviceOperationalIdentity{}, fmt.Errorf("commissioning: operational credentials config is required")
	}
	ipk, caseAdminSubject, adminVendorID, err := loadOperationalCredentialInputs(cfg)
	if err != nil {
		return deviceOperationalIdentity{}, err
	}

	ca, err := loadCertificateAuthority(adminCfg)
	if err != nil {
		return deviceOperationalIdentity{}, err
	}

	nodeID := uint64(types.NewOperationalNodeID())
	nocDER, err := ca.IssueNOC(attResult.csr, nodeID)
	if err != nil {
		return deviceOperationalIdentity{}, fmt.Errorf("commissioning: issue NOC: %w", err)
	}

	if err := addTrustedRootCertificateCommand(sess, defaultEndpointID, ca.RootCertificateDER()); err != nil {
		return deviceOperationalIdentity{}, fmt.Errorf("commissioning: AddTrustedRootCertificate: %w", err)
	}

	if err := addNOCCommand(sess, defaultEndpointID, nocDER, nil, ipk, caseAdminSubject, adminVendorID); err != nil {
		return deviceOperationalIdentity{}, fmt.Errorf("commissioning: AddNOC: %w", err)
	}

	return deviceOperationalIdentity{nodeID: nodeID, noc: nocDER, icac: nil}, nil
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
	peer operationalCASEPeer,
) (mdnspkg.CommissionableNode, error) {
	// Bounded to DefaultDiscoveryTimeout regardless of how much of the
	// overall commissioning ctx's deadline remains: mdns.Discoverer.Search
	// only applies its own short default timeout when the ctx it's given
	// has NO deadline at all (see matter/mdns/discoverer_impl.go); since ctx
	// here is the single deadline spanning the whole PASE-through-CASE
	// exchange (matter/commissioner.go's DefaultCommissioningTimeout), it
	// already has one, so without this the underlying mDNS query blocks
	// collecting responses for whatever's left of that budget — observed on
	// a real device taking well over 100s to return even though the
	// matching operational record was already seen within about a second.
	searchCtx, cancel := context.WithTimeout(ctx, DefaultDiscoveryTimeout)
	defer cancel()
	nodes, err := discoverer.Search(searchCtx, mdnspkg.NewOperationalNodeQuery(peer.serviceInstance))
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
	node mdnspkg.CommissionableNode,
	peer operationalCASEPeer,
	adminCfg config.AdministratorConfig,
	paseTransport caseprotocol.Transport,
) (session.SecureSession, error) {
	t, err := resolveOperationalTransport(ctx, node, paseTransport)
	if err != nil {
		return nil, fmt.Errorf("commissioning: CASE finalization: %w", err)
	}
	initiator := caseprotocol.NewInitiator(
		t,
		adminCfg,
		caseprotocol.WithPeerNodeID(peer.nodeID),
		caseprotocol.WithIPK(peer.ipk),
	)
	keys, err := initiator.EstablishSession(ctx)
	if err != nil {
		// Only close t if we opened it ourselves: a reused paseTransport
		// (e.g. *mDNSDevice) is owned and closed by its own caller, and
		// doesn't implement Close() at all, so this type assertion already
		// naturally skips it.
		if closer, ok := t.(interface{ Close() error }); ok {
			if closeErr := closer.Close(); closeErr != nil {
				log.Error(closeErr)
			}
		}
		return nil, fmt.Errorf("commissioning: CASE finalization: %w", err)
	}
	return session.NewSecureSession(t, keys), nil
}

type operationalCASEPeer struct {
	nodeID          uint64
	serviceInstance string
	ipk             []byte
}

func loadOperationalCASEPeer(cfg config.OperationalCredentialsConfig, adminCfg config.AdministratorConfig, identity deviceOperationalIdentity) (operationalCASEPeer, error) {
	ipk, _, _, err := loadOperationalCredentialInputs(cfg)
	if err != nil {
		return operationalCASEPeer{}, err
	}
	adminInputs, err := caseprotocol.LoadAdministratorMetadata(adminCfg)
	if err != nil {
		return operationalCASEPeer{}, fmt.Errorf("commissioning: CASE administrator config: %w", err)
	}
	compressedFabricID, err := caseprotocol.ComputeCompressedFabricID(adminInputs.RootPublicKey, adminInputs.FabricID)
	if err != nil {
		return operationalCASEPeer{}, fmt.Errorf("commissioning: CASE peer identity: %w", err)
	}
	return operationalCASEPeer{
		nodeID:          identity.nodeID,
		serviceInstance: fmt.Sprintf("%016X-%016X", compressedFabricID, identity.nodeID),
		ipk:             append([]byte(nil), ipk...),
	}, nil
}

// loadOperationalCredentialInputs returns the operational-network-independent
// inputs AddNOC and CASE peer discovery need from cfg: the fabric's Identity
// Protection Key, the CASE admin subject (the administrator's node ID sent as
// AddNOC's CaseAdminSubject), and the commissioner's vendor ID. The RCAC/NOC
// sent to the device now come from the commissioner's CertificateAuthority
// (see loadCertificateAuthority/commissionOperationalCredentials) rather than
// from static config, since the device's NOC is only known once its CSR is
// received during commissioning.
// Returns (ipk, caseAdminSubject, adminVendorID, error).
func loadOperationalCredentialInputs(cfg config.OperationalCredentialsConfig) ([]byte, uint64, uint16, error) {
	ipk, _ := cfg.IPK()
	caseAdminSubject, _ := cfg.CASEAdminNodeID()
	adminVendorID, _ := cfg.AdminVendorID()
	if len(ipk) == 0 {
		return nil, 0, 0, fmt.Errorf("commissioning: operational credentials config missing IPK")
	}
	if caseAdminSubject == 0 {
		return nil, 0, 0, fmt.Errorf("commissioning: operational credentials config missing CASE admin node ID")
	}
	if adminVendorID == 0 {
		return nil, 0, 0, fmt.Errorf("commissioning: operational credentials config missing admin vendor ID")
	}
	return ipk, caseAdminSubject, adminVendorID, nil
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
