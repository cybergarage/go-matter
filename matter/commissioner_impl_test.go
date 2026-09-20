package matter

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

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

func TestConnectRequiresStore(t *testing.T) {
	cmr := &commissioner{}
	_, err := cmr.Connect(context.Background(), 1)
	if !errors.Is(err, ErrFailed) {
		t.Fatalf("Connect(...) error = %v, want ErrFailed", err)
	}
}

func TestConnectRequiresFabricIdentity(t *testing.T) {
	st, err := store.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cmr := &commissioner{store: st}

	_, err = cmr.Connect(context.Background(), 1)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Connect(...) error = %v, want ErrNotFound", err)
	}
}

func TestConnectReturnsNotFoundForUnknownNode(t *testing.T) {
	st, err := store.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cmr := &commissioner{
		store:             st,
		adminConfig:       validAdministratorConfig(),
		operationalConfig: validOperationalCredentialsConfig(),
	}

	_, err = cmr.Connect(context.Background(), 0xDEAD)
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

	st, err := store.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
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

	st, err := store.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
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
