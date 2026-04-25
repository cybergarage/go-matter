package matter

import (
	"context"
	"testing"

	"github.com/cybergarage/go-matter/matter/config"
	"github.com/cybergarage/go-matter/matter/encoding"
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
func (d *stubCommissionableDevice) Commission(context.Context, OnboardingPayload, ...CommissionOption) error {
	d.gotCalls++
	return nil
}

type capturingCommissionableDevice struct {
	stubCommissionableDevice
}

func (d *capturingCommissionableDevice) Commission(_ context.Context, _ OnboardingPayload, opts ...CommissionOption) error {
	d.gotCalls++
	d.gotOpts = append([]CommissionOption(nil), opts...)
	return nil
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

func testPairingCode(t *testing.T) OnboardingPayload {
	t.Helper()
	payload, err := encoding.NewPairingCodeFromString("2167-692-8175")
	if err != nil {
		t.Fatalf("NewPairingCodeFromString(...) error = %v", err)
	}
	return payload
}
