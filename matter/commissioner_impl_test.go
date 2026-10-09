package matter

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	blepkg "github.com/cybergarage/go-matter/matter/ble"
	"github.com/cybergarage/go-matter/matter/config"
	"github.com/cybergarage/go-matter/matter/encoding"
	mdnspkg "github.com/cybergarage/go-matter/matter/mdns"
	caseprotocol "github.com/cybergarage/go-matter/matter/protocol/case"
	"github.com/cybergarage/go-matter/matter/protocol/session"
	"github.com/cybergarage/go-matter/matter/store"
)

type stubCommissionableDevice struct {
	match    bool
	gotOpts  []CommissionOption
	gotCalls int
}

func (d *stubCommissionableDevice) VendorID() VendorID           { return 0 }
func (d *stubCommissionableDevice) ProductID() ProductID         { return 0 }
func (d *stubCommissionableDevice) Discriminator() Discriminator { return 0 }
func (d *stubCommissionableDevice) MarshalObject() any           { return nil }
func (d *stubCommissionableDevice) String() string               { return "stub-device" }
func (d *stubCommissionableDevice) Transmit(context.Context, []byte) error {
	return nil
}
func (d *stubCommissionableDevice) Receive(context.Context) ([]byte, error) { return nil, nil }
func (d *stubCommissionableDevice) Type() DeviceType                        { return 0 }
func (d *stubCommissionableDevice) Address() string                         { return "" }
func (d *stubCommissionableDevice) MatchesOnboardingPayload(OnboardingPayload) bool {
	return d.match
}
func (d *stubCommissionableDevice) Commission(context.Context, OnboardingPayload, ...CommissionOption) (CommissionedIdentity, error) {
	d.gotCalls++
	return CommissionedIdentity{}, nil
}

type capturingCommissionableDevice struct {
	stubCommissionableDevice
}

func (d *capturingCommissionableDevice) Commission(_ context.Context, _ OnboardingPayload, opts ...CommissionOption) (CommissionedIdentity, error) {
	d.gotCalls++
	d.gotOpts = append([]CommissionOption(nil), opts...)
	return CommissionedIdentity{}, nil
}

func TestCommissionMatchingDeviceForwardsOptions(t *testing.T) {
	cmr := &commissioner{}
	dev := &capturingCommissionableDevice{
		stubCommissionableDevice: stubCommissionableDevice{match: true},
	}
	payload := testPairingCode(t)
	opt1 := "hello"
	opt2 := 42

	_, err := cmr.commissionMatchingDevice(context.Background(), payload, []CommissionableDevice{dev}, opt1, opt2)
	if err != nil {
		t.Fatalf("commissionMatchingDevice(...) error = %v", err)
	}
	if dev.gotCalls != 1 {
		t.Fatalf("Commission(...) call count = %d, want 1", dev.gotCalls)
	}
	if len(dev.gotOpts) != 2 {
		t.Fatalf("len(gotOpts) = %d, want 2", len(dev.gotOpts))
	}
	if got := dev.gotOpts[0]; got != opt1 {
		t.Fatalf("gotOpts[0] = %#v, want %#v", got, opt1)
	}
	if got := dev.gotOpts[1]; got != opt2 {
		t.Fatalf("gotOpts[1] = %#v, want %#v", got, opt2)
	}
}

func TestCommissionMatchingDeviceIncludesCommissionerAdministratorConfig(t *testing.T) {
	adminCfg := config.NewAdministratorConfig(config.WithAdministratorNodeID(1))
	cmr := &commissioner{adminConfig: adminCfg}
	dev := &capturingCommissionableDevice{
		stubCommissionableDevice: stubCommissionableDevice{match: true},
	}
	payload := testPairingCode(t)
	opt := "hello"

	_, err := cmr.commissionMatchingDevice(context.Background(), payload, []CommissionableDevice{dev}, opt)
	if err != nil {
		t.Fatalf("commissionMatchingDevice(...) error = %v", err)
	}
	if len(dev.gotOpts) != 2 {
		t.Fatalf("len(gotOpts) = %d, want 2", len(dev.gotOpts))
	}
	if got := dev.gotOpts[0]; got != adminCfg {
		t.Fatalf("gotOpts[0] = %#v, want administrator config", got)
	}
	if got := dev.gotOpts[1]; got != opt {
		t.Fatalf("gotOpts[1] = %#v, want %#v", got, opt)
	}
}

func TestNewCommissionerWithAdministratorConfig(t *testing.T) {
	adminCfg := config.NewAdministratorConfig(config.WithAdministratorNodeID(1))
	cmr, ok := NewCommissioner(WithCommissionerAdministratorConfig(adminCfg)).(*commissioner)
	if !ok {
		t.Fatalf("NewCommissioner(...) returned %T, want *commissioner", cmr)
	}
	if cmr.adminConfig != adminCfg {
		t.Fatal("commissioner admin config was not set")
	}
}

// TestStartUsesInjectedStore checks that a Store passed with
// WithCommissionerStore is used as is: Start restores the fabric identity
// from it and never opens a file store under the home directory.
func TestStartUsesInjectedStore(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	st := store.NewMemStore()
	if err := st.SaveFabric(store.FabricRecord{
		FabricID:      2,
		AdminNodeID:   1,
		AdminVendorID: 0xFFF1,
		IPK:           []byte("0123456789abcdef"),
	}); err != nil {
		t.Fatal(err)
	}
	cmr, ok := NewCommissioner(WithCommissionerStore(st)).(*commissioner)
	if !ok {
		t.Fatalf("NewCommissioner(...) returned %T, want *commissioner", cmr)
	}
	cmr.discoverer = &stubDiscoverer{}

	if err := cmr.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if cmr.store != st {
		t.Fatal("Start() replaced the injected store")
	}
	if cmr.adminConfig == nil {
		t.Fatal("Start() did not restore the administrator config from the injected store")
	}
	if fabricID, ok := cmr.adminConfig.FabricID(); !ok || fabricID != 2 {
		t.Fatalf("adminConfig.FabricID() = (%v, %v), want (2, true)", fabricID, ok)
	}
	entries, err := os.ReadDir(home)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("Start() wrote to the home directory: %v", entries)
	}
}

func TestConnectRequiresStore(t *testing.T) {
	cmr := &commissioner{}
	_, err := cmr.Connect(context.Background(), 1)
	if !errors.Is(err, ErrFailed) {
		t.Fatalf("Connect(...) error = %v, want ErrFailed", err)
	}
}

func TestConnectRequiresFabricIdentity(t *testing.T) {
	st := store.NewMemStore()
	cmr := &commissioner{store: st}

	_, err := cmr.Connect(context.Background(), 1)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Connect(...) error = %v, want ErrNotFound", err)
	}
}

func TestConnectReturnsNotFoundForUnknownNode(t *testing.T) {
	st := store.NewMemStore()
	cmr := &commissioner{
		store:             st,
		adminConfig:       validAdministratorConfig(),
		operationalConfig: validOperationalCredentialsConfig(),
	}

	_, err := cmr.Connect(context.Background(), 0xDEAD)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Connect(...) error = %v, want ErrNotFound", err)
	}
}

func TestConnectSuccess(t *testing.T) {
	prevDiscoverOperational := operationalNodeDiscoverer
	prevEstablishCASE := establishOperationalCASESession
	t.Cleanup(func() {
		operationalNodeDiscoverer = prevDiscoverOperational
		establishOperationalCASESession = prevEstablishCASE
	})

	st := store.NewMemStore()
	adminCfg := validAdministratorConfig()
	cmr := &commissioner{
		store:             st,
		discoverer:        &stubDiscoverer{},
		adminConfig:       adminCfg,
		operationalConfig: validOperationalCredentialsConfig(),
	}

	compressedFabricID, err := computeCompressedFabricID(adminCfg)
	if err != nil {
		t.Fatal(err)
	}
	const nodeID = uint64(0x1234)
	const fabricID = uint64(2)
	if err := st.SaveCommissionee(store.CommissioneeRecord{
		NodeID:             nodeID,
		FabricID:           fabricID,
		CompressedFabricID: compressedFabricID,
	}); err != nil {
		t.Fatal(err)
	}

	var gotPeer operationalCASEPeer
	operationalNodeDiscoverer = func(_ context.Context, _ mdnspkg.Discoverer, peer operationalCASEPeer) (mdnspkg.CommissionableNode, error) {
		gotPeer = peer
		return nil, nil
	}
	establishOperationalCASESession = func(context.Context, mdnspkg.CommissionableNode, operationalCASEPeer, config.AdministratorConfig, caseprotocol.Transport) (session.SecureSession, error) {
		return stubSecureSession{}, nil
	}

	node, err := cmr.Connect(context.Background(), nodeID)
	if err != nil {
		t.Fatalf("Connect(...) error = %v", err)
	}
	if node.NodeID() != NodeID(nodeID) {
		t.Errorf("node.NodeID() = %v, want %v", node.NodeID(), nodeID)
	}
	if node.FabricID() != fabricID {
		t.Errorf("node.FabricID() = %v, want %v", node.FabricID(), fabricID)
	}

	wantServiceInstance := fmt.Sprintf("%016X-%016X", compressedFabricID, nodeID)
	if gotPeer.serviceInstance != wantServiceInstance {
		t.Errorf("discovered peer.serviceInstance = %q, want %q (built from the record's CompressedFabricID)", gotPeer.serviceInstance, wantServiceInstance)
	}
}

// TestConnectAppliesDefaultTimeout guards against a regression where Connect
// let a caller's undeadlined ctx block for however long operational
// discovery and CASE establishment take, instead of bounding it to
// DefaultConnectTimeout the same way Discover bounds itself to
// DefaultDiscoveryTimeout.
func TestConnectAppliesDefaultTimeout(t *testing.T) {
	prevDiscoverOperational := operationalNodeDiscoverer
	prevEstablishCASE := establishOperationalCASESession
	t.Cleanup(func() {
		operationalNodeDiscoverer = prevDiscoverOperational
		establishOperationalCASESession = prevEstablishCASE
	})

	st := store.NewMemStore()
	adminCfg := validAdministratorConfig()
	cmr := &commissioner{
		store:             st,
		discoverer:        &stubDiscoverer{},
		adminConfig:       adminCfg,
		operationalConfig: validOperationalCredentialsConfig(),
	}
	compressedFabricID, err := computeCompressedFabricID(adminCfg)
	if err != nil {
		t.Fatal(err)
	}
	const nodeID = uint64(0x1234)
	if err := st.SaveCommissionee(store.CommissioneeRecord{
		NodeID:             nodeID,
		CompressedFabricID: compressedFabricID,
	}); err != nil {
		t.Fatal(err)
	}

	var gotDeadline time.Time
	var gotOK bool
	operationalNodeDiscoverer = func(ctx context.Context, _ mdnspkg.Discoverer, _ operationalCASEPeer) (mdnspkg.CommissionableNode, error) {
		gotDeadline, gotOK = ctx.Deadline()
		return nil, fmt.Errorf("stop before CASE")
	}
	establishOperationalCASESession = func(context.Context, mdnspkg.CommissionableNode, operationalCASEPeer, config.AdministratorConfig, caseprotocol.Transport) (session.SecureSession, error) {
		t.Fatal("establishOperationalCASESession should not be called")
		return nil, nil
	}

	before := time.Now()
	_, _ = cmr.Connect(context.Background(), nodeID)

	if !gotOK {
		t.Fatal("Connect passed operationalNodeDiscoverer a context with no deadline, want one bounded to DefaultConnectTimeout")
	}
	maxExpected := before.Add(DefaultConnectTimeout + time.Second)
	if gotDeadline.After(maxExpected) {
		t.Errorf("discovery context deadline = %s, want within DefaultConnectTimeout (%s) of now", gotDeadline, DefaultConnectTimeout)
	}
}

func testPairingCode(t *testing.T) OnboardingPayload {
	t.Helper()
	payload, err := encoding.NewPairingCodeFromString("2167-692-8175")
	if err != nil {
		t.Fatalf("NewPairingCodeFromString(...) error = %v", err)
	}
	return payload
}

// The caller must be able to cancel the post-discovery PASE-through-CASE flow.
type cancelAwareDevice struct{ stubCommissionableDevice }

func (d *cancelAwareDevice) Commission(ctx context.Context, _ OnboardingPayload, _ ...CommissionOption) (CommissionedIdentity, error) {
	return CommissionedIdentity{}, ctx.Err()
}
func TestCommissionMatchingDevicePropagatesCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cmr := &commissioner{}
	d := &cancelAwareDevice{stubCommissionableDevice: stubCommissionableDevice{match: true}}
	_, err := cmr.commissionMatchingDevice(ctx, testPairingCode(t), []CommissionableDevice{d})
	if !errors.Is(err, context.Canceled) {
		t.Fatal("commissioning did not preserve caller cancellation")
	}
}
func TestCommissionNoMatchDoesNotRevealPayload(t *testing.T) {
	p := testPairingCode(t)
	_, err := (&commissioner{}).commissionMatchingDevice(context.Background(), p, nil)
	if err == nil || strings.Contains(err.Error(), p.String()) {
		t.Fatal("no-match error revealed onboarding payload")
	}
}

// Commission discovery uses a child deadline so a completed scan does not
// expire the parent budget needed for PASE/CASE. Both transports are injected.
type noScanCentral struct{}

func (noScanCentral) DiscoveredDevices() []blepkg.Device                     { return nil }
func (noScanCentral) LookupDeviceByDiscriminator(any) (blepkg.Device, error) { return nil, ErrNotFound }
func (noScanCentral) Scan(context.Context, ...blepkg.ScannerOption) error    { return nil }
func TestCommissionDiscoveryHasSeparateDeadline(t *testing.T) {
	var discoveryDeadline time.Time
	discoverer := &capturingDiscoverer{searchFunc: func(ctx context.Context, _ mdnspkg.Query) ([]mdnspkg.CommissionableNode, error) {
		discoveryDeadline, _ = ctx.Deadline()
		return nil, nil
	}}
	cmr := NewCommissioner(WithCommissionerCentral(noScanCentral{}), WithCommissionerDiscoverer(discoverer), WithCommissionerStore(store.NewMemStore()))
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	before := time.Now()
	_, err := cmr.Commission(ctx, testPairingCode(t))
	if !errors.Is(err, ErrNotFound) {
		t.Fatal("unexpected empty discovery result")
	}
	if ctx.Err() != nil {
		t.Fatal("discovery expired parent context")
	}
	budget := discoveryDeadline.Sub(before)
	if budget < DefaultDiscoveryTimeout-time.Second || budget > DefaultDiscoveryTimeout+time.Second {
		t.Fatal("discovery did not use a separate phase budget")
	}
}
