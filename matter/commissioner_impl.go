// Copyright (C) 2024 The go-matter Authors. All rights reserved.
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
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter/ble"
	"github.com/cybergarage/go-matter/matter/config"
	"github.com/cybergarage/go-matter/matter/errors"
	"github.com/cybergarage/go-matter/matter/mdns"
	caseprotocol "github.com/cybergarage/go-matter/matter/protocol/case"
	"github.com/cybergarage/go-matter/matter/store"
)

// DefaultAppName is the directory name (under the user's home directory,
// prefixed with ".") a Commissioner persists its fabric identity and
// commissioned-device records to, unless overridden by
// WithCommissionerAppName or WithCommissionerStoreDir.
const DefaultAppName = "go-matter"

// CommissionerOption defines a functional option for configuring a Commissioner.
type CommissionerOption func(*commissioner)

// WithCommissionerAdministratorConfig sets the default AdministratorConfig used
// when commissioning devices.
func WithCommissionerAdministratorConfig(adminCfg config.AdministratorConfig) CommissionerOption {
	return func(cmr *commissioner) {
		cmr.adminConfig = adminCfg
	}
}

// WithCommissionerDiscoverer overrides the mDNS discoverer a Commissioner
// uses for both commissionable-node discovery (Discover/Commission) and
// operational-node discovery post-AddNOC (discoverOperationalNode in
// commissioning_impl.go) — the same discoverer field serves both, so one
// override covers the whole commissioning flow. Primarily for tests that
// need to inject a fake discoverer pointing at an in-process mock device
// instead of scanning the real network.
func WithCommissionerDiscoverer(d mdns.Discoverer) CommissionerOption {
	return func(cmr *commissioner) {
		cmr.discoverer = d
	}
}

// WithCommissionerOperationalCredentialsConfig sets the default
// OperationalCredentialsConfig used when commissioning devices, mirroring
// WithCommissionerAdministratorConfig — together these are the fabric-wide
// identity a Commissioner reuses (and, once persistence resolves in
// Start(), restores from disk when not explicitly set) across every device
// it commissions.
func WithCommissionerOperationalCredentialsConfig(cfg config.OperationalCredentialsConfig) CommissionerOption {
	return func(cmr *commissioner) {
		cmr.operationalConfig = cfg
	}
}

// WithCommissionerAppName sets the directory name (under the user's home
// directory, prefixed with ".") a Commissioner persists its fabric identity
// and commissioned-device records to. Defaults to DefaultAppName.
func WithCommissionerAppName(name string) CommissionerOption {
	return func(cmr *commissioner) {
		cmr.appName = name
	}
}

// WithCommissionerStoreDir overrides the resolved persistence directory
// directly, bypassing ~/.{appName} resolution entirely. Primarily for tests
// that need a hermetic, per-test-run directory (e.g. t.TempDir()) instead
// of touching the real user's home directory.
func WithCommissionerStoreDir(dir string) CommissionerOption {
	return func(cmr *commissioner) {
		cmr.storeDir = dir
	}
}

// commissioner represents a commissioner.
type commissioner struct {
	ble.Central
	discoverer        mdns.Discoverer
	adminConfig       config.AdministratorConfig
	operationalConfig config.OperationalCredentialsConfig
	appName           string
	storeDir          string
	store             store.Store
}

// NewCommissioner returns a new commissioner.
func NewCommissioner(opts ...CommissionerOption) Commissioner {
	com := &commissioner{
		Central:           ble.NewCentral(),
		discoverer:        mdns.NewDiscoverer(),
		adminConfig:       nil,
		operationalConfig: nil,
		appName:           DefaultAppName,
		storeDir:          "",
		store:             nil,
	}
	for _, opt := range opts {
		opt(com)
	}
	return com
}

// Scannar returns the BLE scanner.
func (cmr *commissioner) Scannar() ble.Scanner {
	return cmr.Central
}

// Discoverer returns the mDNS discoverer.
func (cmr *commissioner) Discoverer() mdns.Discoverer {
	return cmr.discoverer
}

// Discover discovers commissionable devices.
// 5.4.3. Discovery by Commissioner.
func (cmr *commissioner) Discover(ctx context.Context, query Query) ([]CommissionableDevice, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, DefaultDiscoveryTimeout)
		defer cancel()
	}

	scanNodes := func(ctx context.Context) ([]CommissionableDevice, error) {
		scanHandler := ble.ScanHandler(func(bleDev ble.BLEDevice) {
			log.Debugf("BLE device responded: %s", bleDev.String())
		})
		var devs []CommissionableDevice
		scanner := cmr.Scannar()
		err := scanner.Scan(ctx, scanHandler)
		if err != nil {
			return nil, err
		}
		for _, bleDev := range scanner.DiscoveredDevices() {
			if !bleDev.IsCommissionable() {
				continue
			}
			bleService, err := bleDev.Service()
			if err != nil {
				continue
			}
			devs = append(devs, newBLEDevice(bleDev, bleService, cmr.discoverer))
		}
		return devs, nil
	}

	discoverNodes := func(ctx context.Context) ([]CommissionableDevice, error) {
		msgHandler := mdns.MessageHandler(func(msg mdns.Message) {
			log.Debugf("mDNS device responded: %s", msg.String())
			log.HexDebug(msg.Bytes())
		})
		var devs []CommissionableDevice
		dnsQueryOpts := []mdns.QueryOption{
			mdns.WithQueryService(mdns.CommissionableNodeService),
			mdns.WithQueryMessageHandler(msgHandler),
		}
		if payload, ok := query.OnboardingPayload(); ok {
			dnsQueryOpts = append(dnsQueryOpts,
				mdns.WithQueryOnboardingPayload(payload),
			)
		}
		nodes, err := cmr.discoverer.Search(ctx, mdns.NewQuery(dnsQueryOpts...))
		if err != nil {
			return nil, err
		}
		for _, entry := range nodes {
			devs = append(devs, newMDNSDevice(entry, cmr.discoverer))
		}
		return devs, nil
	}

	// Run BLE scan and mDNS discovery in parallel
	type result struct {
		devs []CommissionableDevice
		err  error
	}

	// Use a single channel to collect both results symmetrically
	done := make(chan result, 2)

	go func() {
		d, e := scanNodes(ctx)
		done <- result{devs: d, err: e}
	}()

	go func() {
		d, e := discoverNodes(ctx)
		done <- result{devs: d, err: e}
	}()

	var devs []CommissionableDevice

	// Collect two results; treat timeouts as normal (skip)
	for range 2 {
		r := <-done
		if r.err != nil && !errors.Is(r.err, context.DeadlineExceeded) {
			return nil, r.err
		}
		devs = append(devs, r.devs...)
	}

	return devs, nil
}

// 5.5. Commissioning Flows.
func (cmr *commissioner) Commission(ctx context.Context, payload OnboardingPayload, opts ...CommissionOption) (Commissionee, error) {
	query := NewQuery(
		WithQueryOnboardingPayload(payload),
	)
	devs, err := cmr.Discover(ctx, query)
	if err != nil {
		return nil, err
	}

	log.Infof("Discovered device: %d", len(devs))
	for n, dev := range devs {
		log.Infof("[%d] %s", n, dev.String())
	}

	return cmr.commissionMatchingDevice(ctx, payload, devs, opts...)
}

func (cmr *commissioner) commissionMatchingDevice(ctx context.Context, payload OnboardingPayload, devs []CommissionableDevice, opts ...CommissionOption) (Commissionee, error) {
	opts = cmr.commissionOptions(opts...)
	adminCfg, operationalCfg := effectiveConfigOptions(opts)
	for _, dev := range devs {
		isMatched := dev.MatchesOnboardingPayload(payload)
		if !isMatched {
			log.Infof("Skipping device (does not match payload): %s", dev.String())
			continue
		}
		log.Infof("Trying to commission device: %s", dev.String())

		ctxCommission, cancel := context.WithTimeout(context.Background(), DefaultCommissioningTimeout)
		defer cancel()

		identity, err := dev.Commission(ctxCommission, payload, opts...)
		if err != nil {
			return nil, fmt.Errorf("%w to commission device (%s): %w", ErrFailed, dev.String(), err)
		}
		if cmr.store != nil {
			cmr.persistCommissioning(adminCfg, operationalCfg, dev, identity)
		}
		return newCommissioneeWithIdentity(dev, identity), nil
	}

	return nil, fmt.Errorf("%w: no matching commissionable device found (payload=%s)", ErrNotFound, payload.String())
}

// Connect reconnects to an already-commissioned node via a fresh CASE
// handshake, using the fabric identity (cmr.adminConfig/cmr.operationalConfig
// — already resolved from either explicit config or the persisted fabric
// record by Start()) and the persisted per-device record (cmr.store) to
// locate and authenticate the peer. It reuses operationalNodeDiscoverer and
// establishOperationalCASESession unmodified (the same package vars
// Commission()'s CASE finalization uses), so this path is provably
// independent of Commission()'s own CASE-close-via-defer behavior.
func (cmr *commissioner) Connect(ctx context.Context, nodeID uint64) (Node, error) {
	if cmr.store == nil {
		return nil, fmt.Errorf("%w: commissioner: Connect requires Start() to have opened a persistence store", ErrFailed)
	}
	if cmr.adminConfig == nil || cmr.operationalConfig == nil {
		return nil, fmt.Errorf("%w: commissioner: Connect: no fabric identity available (commission a device, or call Start() against a store that already has one)", ErrNotFound)
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, DefaultConnectTimeout)
		defer cancel()
	}

	compressedFabricID, err := computeCompressedFabricID(cmr.adminConfig)
	if err != nil {
		return nil, fmt.Errorf("commissioner: Connect: compute compressed fabric ID: %w", err)
	}
	rec, ok, err := cmr.store.LoadCommissionee(compressedFabricID, nodeID)
	if err != nil {
		return nil, fmt.Errorf("commissioner: Connect: load commissionee record: %w", err)
	}
	if !ok {
		return nil, fmt.Errorf("%w: commissioner: Connect: no commissionee record for node 0x%016X", ErrNotFound, nodeID)
	}

	ipk, _ := cmr.operationalConfig.IPK()
	peer := operationalCASEPeerFromRecord(rec, ipk)

	node, err := operationalNodeDiscoverer(ctx, cmr.discoverer, peer)
	if err != nil {
		return nil, fmt.Errorf("commissioner: Connect: %w", err)
	}

	// paseTransport is nil: Connect never has a PASE-phase connection to
	// reuse (unlike finalizeCommissioningOverCASE, called mid-commissioning)
	// — resolveOperationalTransport's type assertion on a nil Transport
	// simply fails to match remoteAddrProvider and falls through to dialing
	// a fresh connection.
	caseSess, err := establishOperationalCASESession(ctx, node, peer, cmr.adminConfig, nil)
	if err != nil {
		return nil, fmt.Errorf("commissioner: Connect: %w", err)
	}

	return newNode(NodeID(rec.NodeID), rec.FabricID, caseSess), nil
}

// effectiveConfigOptions extracts the AdministratorConfig/OperationalCredentialsConfig
// that will actually be used for a commissioning attempt out of the merged
// option list commissionOptions() built (Commissioner-wide defaults already
// prepended, per-call opts already appended after and so already taking
// precedence per baseDevice.parseCommissionOptions' last-write-wins
// behavior). Used only to persist the identity actually used, not to alter
// what's passed to dev.Commission.
func effectiveConfigOptions(opts []CommissionOption) (config.AdministratorConfig, config.OperationalCredentialsConfig) {
	var adminCfg config.AdministratorConfig
	var operationalCfg config.OperationalCredentialsConfig
	for _, opt := range opts {
		switch o := opt.(type) {
		case config.AdministratorConfig:
			adminCfg = o
		case config.OperationalCredentialsConfig:
			operationalCfg = o
		}
	}
	return adminCfg, operationalCfg
}

// persistCommissioning saves the fabric-wide identity and the newly
// commissioned device's record to cmr.store. Failures are logged, not
// returned: the device is genuinely commissioned regardless of whether the
// local cache write succeeded, so a persistence error must not be reported
// as a commissioning failure.
func (cmr *commissioner) persistCommissioning(adminCfg config.AdministratorConfig, operationalCfg config.OperationalCredentialsConfig, dev CommissionableDevice, identity CommissionedIdentity) {
	if adminCfg == nil || operationalCfg == nil {
		return
	}

	fabricRec, err := buildFabricRecord(adminCfg, operationalCfg)
	if err != nil {
		log.Errorf("commissioner: build fabric record: %v", err)
	} else if err := cmr.store.SaveFabric(fabricRec); err != nil {
		log.Errorf("commissioner: save fabric identity: %v", err)
	}

	compressedFabricID, err := computeCompressedFabricID(adminCfg)
	if err != nil {
		log.Errorf("commissioner: compute compressed fabric ID for persistence: %v", err)
		return
	}
	commissioneeRec := store.CommissioneeRecord{
		NodeID:             uint64(identity.NodeID),
		FabricID:           identity.FabricID,
		CompressedFabricID: compressedFabricID,
		VendorID:           uint16(dev.VendorID()),
		ProductID:          uint16(dev.ProductID()),
		Discriminator:      uint16(dev.Discriminator()),
		NOC:                identity.NOC,
		ICAC:               identity.ICAC,
		CommissionedAt:     time.Now().UTC(),
	}
	if err := cmr.store.SaveCommissionee(commissioneeRec); err != nil {
		log.Errorf("commissioner: save commissionee record: %v", err)
	}
}

func buildFabricRecord(adminCfg config.AdministratorConfig, operationalCfg config.OperationalCredentialsConfig) (store.FabricRecord, error) {
	fabricID, ok := adminCfg.FabricID()
	if !ok {
		return store.FabricRecord{}, fmt.Errorf("administrator config missing fabric ID")
	}
	adminNodeID, ok := adminCfg.NodeID()
	if !ok {
		return store.FabricRecord{}, fmt.Errorf("administrator config missing node ID")
	}
	adminVendorID, ok := operationalCfg.AdminVendorID()
	if !ok {
		return store.FabricRecord{}, fmt.Errorf("operational credentials config missing admin vendor ID")
	}
	rootCert, _ := adminCfg.RootCertificate()
	rootKey, _ := adminCfg.RootPrivateKey()
	noc, _ := adminCfg.NOC()
	icac, _ := adminCfg.ICAC()
	privateKey, _ := adminCfg.PrivateKey()
	ipk, _ := operationalCfg.IPK()
	return store.FabricRecord{
		FabricID:        fabricID,
		AdminNodeID:     adminNodeID,
		AdminVendorID:   uint16(adminVendorID),
		RootCertificate: rootCert,
		RootPrivateKey:  rootKey,
		NOC:             noc,
		ICAC:            icac,
		PrivateKey:      privateKey,
		IPK:             ipk,
		UpdatedAt:       time.Now().UTC(),
	}, nil
}

func computeCompressedFabricID(adminCfg config.AdministratorConfig) (uint64, error) {
	adminInputs, err := caseprotocol.LoadAdministratorMetadata(adminCfg)
	if err != nil {
		return 0, err
	}
	return caseprotocol.ComputeCompressedFabricID(adminInputs.RootPublicKey, adminInputs.FabricID)
}

func (cmr *commissioner) commissionOptions(opts ...CommissionOption) []CommissionOption {
	var defaults []CommissionOption
	if cmr.adminConfig != nil {
		defaults = append(defaults, cmr.adminConfig)
	}
	if cmr.operationalConfig != nil {
		defaults = append(defaults, cmr.operationalConfig)
	}
	if len(defaults) == 0 {
		return opts
	}
	return append(defaults, opts...)
}

// Start resolves this Commissioner's persistence directory (storeDir if
// explicitly set, else ~/.{appName}), opens its Store, and — only for
// whichever of adminConfig/operationalConfig wasn't explicitly passed via
// WithCommissionerAdministratorConfig/WithCommissionerOperationalCredentialsConfig —
// falls back to a previously persisted fabric identity, if one exists.
// Explicit config always wins; disk is a best-effort fallback, and a load
// failure is logged, not fatal.
func (cmr *commissioner) Start() error {
	dir := cmr.storeDir
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("commissioner: resolve home directory: %w", err)
		}
		dir = filepath.Join(home, "."+cmr.appName)
	}
	st, err := store.NewStore(dir)
	if err != nil {
		return fmt.Errorf("commissioner: open persistence store: %w", err)
	}
	cmr.store = st

	if cmr.adminConfig == nil || cmr.operationalConfig == nil {
		rec, ok, err := st.LoadFabric()
		if err != nil {
			log.Errorf("commissioner: load persisted fabric identity: %v", err)
		} else if ok {
			if cmr.adminConfig == nil {
				cmr.adminConfig = administratorConfigFromRecord(rec)
			}
			if cmr.operationalConfig == nil {
				cmr.operationalConfig = operationalCredentialsConfigFromRecord(rec)
			}
		}
	}

	if err := cmr.discoverer.Start(); err != nil {
		return err
	}
	return nil
}

func administratorConfigFromRecord(rec store.FabricRecord) config.AdministratorConfig {
	opts := []config.AdministratorConfigOption{
		config.WithAdministratorNodeID(rec.AdminNodeID),
		config.WithAdministratorFabricID(rec.FabricID),
		config.WithAdministratorRootCertificate(rec.RootCertificate),
		config.WithAdministratorRootPrivateKey(rec.RootPrivateKey),
		config.WithAdministratorNOC(rec.NOC),
		config.WithAdministratorPrivateKey(rec.PrivateKey),
	}
	if len(rec.ICAC) != 0 {
		opts = append(opts, config.WithAdministratorICAC(rec.ICAC))
	}
	return config.NewAdministratorConfig(opts...)
}

func operationalCredentialsConfigFromRecord(rec store.FabricRecord) config.OperationalCredentialsConfig {
	return config.NewOperationalCredentialConfig(
		config.WithIPK(rec.IPK),
		config.WithCASEAdminNodeID(rec.AdminNodeID),
		config.WithAdminVendorID(rec.AdminVendorID),
	)
}

// Stop stops the commissioner.
func (cmr *commissioner) Stop() error {
	err := cmr.discoverer.Stop()
	if err != nil {
		return err
	}
	return nil
}
