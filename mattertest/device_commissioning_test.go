// Copyright (C) 2026 The go-matter Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mattertest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cybergarage/go-matter/matter"
	"github.com/cybergarage/go-matter/matter/ble"
	"github.com/cybergarage/go-matter/matter/config"
	"github.com/cybergarage/go-matter/matter/credentials/testcreds"
	"github.com/cybergarage/go-matter/matter/device"
	"github.com/cybergarage/go-matter/matter/encoding"
	"github.com/cybergarage/go-matter/matter/store"
	"github.com/cybergarage/go-matter/matter/types"
	"github.com/cybergarage/go-matter/mattertest/mockdevice"
)

// noBLECentral is a BLE central which finds nothing, so a Commissioner
// discovers over mDNS only, even where no Bluetooth adapter is available.
type noBLECentral struct{}

func (noBLECentral) DiscoveredDevices() []ble.Device { return nil }

func (noBLECentral) LookupDeviceByDiscriminator(any) (ble.Device, error) {
	return nil, errors.New("no BLE devices")
}

func (noBLECentral) Scan(context.Context, ...ble.ScannerOption) error { return nil }

const (
	deviceCommissioningDiscriminator = 0x0DEF
	deviceCommissioningPasscode      = 20202021
)

// TestCommissionerCommissionsDevice commissions a matter/device Device
// with go-matter's own Commissioner, over real mDNS and UDP, from
// discovery to CommissioningComplete over CASE: the device attests with
// the Matter SDK's test credentials, joins the commissioner's fabric,
// advertises itself operationally, and commits the fabric.
func TestCommissionerCommissionsDevice(t *testing.T) {
	if testing.Short() {
		t.Skip("uses mDNS on the network; skipped with -short")
	}
	attestation, err := testcreds.AttestationProvider()
	if err != nil {
		t.Fatal(err)
	}
	deviceStore := store.NewMemDeviceStore()
	dev, err := device.New(
		device.WithDeviceStore(deviceStore),
		device.WithPasscode(types.Passcode(deviceCommissioningPasscode)),
		device.WithAddress(":0"),
		device.WithDiscriminator(deviceCommissioningDiscriminator),
		device.WithVendorID(testcreds.VendorID),
		device.WithProductID(testcreds.ProductID),
		device.WithAttestationProvider(attestation),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := dev.Start(); err != nil {
		t.Skipf("the device cannot advertise here: %v", err)
	}
	defer func() {
		if err := dev.Stop(); err != nil {
			t.Errorf("Device.Stop() error = %v", err)
		}
	}()

	mpc := buildManualPairingCodeForTest(t, deviceCommissioningDiscriminator, deviceCommissioningPasscode, testcreds.VendorID, testcreds.ProductID)
	pairingCode, err := encoding.NewPairingCodeFromString(mpc)
	if err != nil {
		t.Fatalf("encoding.NewPairingCodeFromString(%q) error = %v", mpc, err)
	}
	adminCfg, err := NewAdministratorConfig()
	if err != nil {
		t.Fatal(err)
	}
	opCfg := config.NewOperationalCredentialConfig(
		config.WithIPK(defaultOperationalIPK),
		config.WithCASEAdminNodeID(testAdministratorNodeID),
		config.WithAdminVendorID(defaultAdminVendorID),
	)

	cmr := matter.NewCommissioner(
		matter.WithCommissionerCentral(noBLECentral{}),
		matter.WithCommissionerStoreDir(t.TempDir()),
	)
	if err := cmr.Start(); err != nil {
		t.Skipf("the commissioner cannot start here: %v", err)
	}
	defer func() {
		if err := cmr.Stop(); err != nil {
			t.Errorf("Commissioner.Stop() error = %v", err)
		}
	}()

	// The caller deadline bounds discovery and the complete PASE-through-CASE flow.
	ctx, cancel := context.WithTimeout(context.Background(), matter.DefaultCommissioningTimeout)
	defer cancel()
	cme, err := cmr.Commission(ctx, pairingCode, adminCfg, opCfg)
	if err != nil {
		t.Fatalf("Commission() error = %v", err)
	}
	t.Logf("commissioned %s", cme.String())

	// CommissioningComplete committed the fabric to the device's store.
	fabrics, err := deviceStore.ListDeviceFabrics()
	if err != nil || len(fabrics) != 1 {
		t.Fatalf("the device holds (%d fabrics, %v), want 1", len(fabrics), err)
	}
	fabricID, _ := adminCfg.FabricID()
	nodeID, _ := cme.NodeID()
	if f := fabrics[0]; f.FabricID != fabricID || f.NodeID != uint64(nodeID) {
		t.Fatalf("the device joined fabric 0x%X as node 0x%X, want fabric 0x%X as node 0x%X", f.FabricID, f.NodeID, fabricID, uint64(nodeID))
	}
}

// failingBLECentral is a BLE central which cannot scan, as on a host whose
// Bluetooth is off or missing.
type failingBLECentral struct{ noBLECentral }

func (failingBLECentral) Scan(context.Context, ...ble.ScannerOption) error {
	return errors.New("bluetooth is not available")
}

// TestCommissionerDiscoversWithoutBLE checks that a failing BLE scan does
// not stop the commissioner from finding a device over mDNS.
func TestCommissionerDiscoversWithoutBLE(t *testing.T) {
	dev, err := mockdevice.New(
		mockdevice.WithDiscriminator(mockCommissioningDiscriminator),
		mockdevice.WithPasscode(mockCommissioningPasscode),
		mockdevice.WithVendorID(mockCommissioningVendorID),
		mockdevice.WithProductID(mockCommissioningProductID),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := dev.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dev.Stop() }()

	cmr := matter.NewCommissioner(
		matter.WithCommissionerDiscoverer(mockdevice.NewFakeDiscoverer(dev)),
		matter.WithCommissionerCentral(failingBLECentral{}),
		matter.WithCommissionerStoreDir(t.TempDir()),
	)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	devs, err := cmr.Discover(ctx, matter.NewQuery())
	if err != nil {
		t.Fatalf("Discover() error = %v, want the mDNS devices despite BLE failing", err)
	}
	if len(devs) == 0 {
		t.Fatal("Discover() found no device over mDNS")
	}
}
