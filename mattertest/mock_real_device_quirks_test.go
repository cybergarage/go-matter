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

package mattertest

import (
	"context"
	"testing"
	"time"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter"
	"github.com/cybergarage/go-matter/matter/cluster/basicinformation"
	"github.com/cybergarage/go-matter/matter/cluster/generaldiagnostics"
	"github.com/cybergarage/go-matter/matter/config"
	"github.com/cybergarage/go-matter/matter/encoding"
	"github.com/cybergarage/go-matter/mattertest/mockdevice"
)

// mockRealDeviceQuirksDiscriminator/.../ProductID are a synthetic identity
// for this test's mock device, distinct from every other mock test's own
// identity — this mock reproduces a real device's *behavior* (see
// mockdevice.WithFakeBLECentralWriteWithoutResponseOnly/
// WithGeneralDiagnosticsRebootCountNull), not its actual VendorID/ProductID,
// matching this project's standing rule against ever addressing a mock via
// a real device's own MPC identity.
const (
	mockRealDeviceQuirksDiscriminator = 0x0AB1
	mockRealDeviceQuirksPasscode      = 20202023
	mockRealDeviceQuirksVendorID      = 0xFFF1
	mockRealDeviceQuirksProductID     = 0x8004
)

// TestMockRealDeviceQuirks reproduces two behaviors a real, commercially
// available device (VendorID 0x1392/5010, ProductID 0x0103/259) exhibited
// against a live NUC/BlueZ run and that no other mock test exercises:
//
//   - Its C1 (BTP handshake) characteristic rejects a with-response GATT
//     write outright, requiring matter/ble/transport.go's Handshake to fall
//     back to a without-response write.
//   - Its General Diagnostics RebootCount attribute reads back as null
//     (spec-legal, 11.13.6) rather than a concrete value.
//
// Both were real interop bugs this project only found by testing against
// that hardware; this test keeps them covered by `go test` without needing
// the device (or any Bluetooth adapter) present.
func TestMockRealDeviceQuirks(t *testing.T) {
	log.EnableStdoutDebug(true)
	defer log.EnableStdoutDebug(false)

	dev, err := mockdevice.New(
		mockdevice.WithDiscriminator(mockRealDeviceQuirksDiscriminator),
		mockdevice.WithPasscode(mockRealDeviceQuirksPasscode),
		mockdevice.WithVendorID(mockRealDeviceQuirksVendorID),
		mockdevice.WithProductID(mockRealDeviceQuirksProductID),
		mockdevice.WithGeneralDiagnosticsRebootCountNull(),
	)
	if err != nil {
		t.Fatalf("mockdevice.New() error = %v", err)
	}

	central, handshakeObserver, err := mockdevice.NewFakeBLECentral(dev, mockdevice.WithFakeBLECentralWriteWithoutResponseOnly())
	if err != nil {
		t.Fatalf("mockdevice.NewFakeBLECentral() error = %v", err)
	}
	defer func() {
		if err := dev.Stop(); err != nil {
			t.Errorf("Device.Stop() error = %v", err)
		}
	}()

	mpc := buildManualPairingCodeForTest(t, mockRealDeviceQuirksDiscriminator, mockRealDeviceQuirksPasscode, mockRealDeviceQuirksVendorID, mockRealDeviceQuirksProductID)
	pairingCode, err := encoding.NewPairingCodeFromString(mpc)
	if err != nil {
		t.Fatalf("encoding.NewPairingCodeFromString(%q) error = %v", mpc, err)
	}

	adminCfg, err := NewAdministratorConfig()
	if err != nil {
		t.Fatalf("NewAdministratorConfig() error = %v", err)
	}
	opCfg := config.NewOperationalCredentialConfig(
		config.WithIPK(defaultOperationalIPK),
		config.WithCASEAdminNodeID(testAdministratorNodeID),
		config.WithAdminVendorID(defaultAdminVendorID),
	)
	// See mock_ble_commissioning_test.go's matching comment: the BLE
	// transport unconditionally requires Wi-Fi network config.
	wifiCfg := config.NewWiFiNetworkConfig(
		config.WithSSID([]byte("mock-ssid")),
		config.WithCredentials([]byte("mock-password")),
	)

	storeDir := t.TempDir()
	cmr := matter.NewCommissioner(
		matter.WithCommissionerCentral(central),
		matter.WithCommissionerDiscoverer(mockdevice.NewFakeOperationalDiscoverer(dev)),
		matter.WithCommissionerStoreDir(storeDir),
		matter.WithCommissionerAdministratorConfig(adminCfg),
		matter.WithCommissionerOperationalCredentialsConfig(opCfg),
	)
	if err := cmr.Start(); err != nil {
		t.Fatalf("Commissioner.Start() error = %v", err)
	}
	defer func() {
		if err := cmr.Stop(); err != nil {
			t.Errorf("Commissioner.Stop() error = %v", err)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cme, err := cmr.Commission(ctx, pairingCode, adminCfg, opCfg, wifiCfg)
	if err != nil {
		t.Fatalf("Failed to commission simulated quirky device: %v", err)
	}
	t.Logf("Successfully commissioned simulated quirky device: %s", cme.String())

	orderCtx, orderCancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer orderCancel()
	orderOK, err := handshakeObserver.HandshakeOrderOK(orderCtx)
	if err != nil {
		t.Fatalf("HandshakeOrderOK() error = %v", err)
	}
	if !orderOK {
		t.Error("HandshakeOrderOK() = false: the successful (without-response, after the with-response fallback) BTP handshake write was not seen before Subscribe")
	}

	nodeID, ok := cme.NodeID()
	if !ok {
		t.Fatal("Commissionee.NodeID() ok = false after successful commissioning")
	}
	connectCtx, connectCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer connectCancel()
	node, err := cmr.Connect(connectCtx, uint64(nodeID))
	if err != nil {
		t.Fatalf("Commissioner.Connect() error = %v", err)
	}
	defer func() {
		if err := node.Close(); err != nil {
			t.Errorf("Node.Close() error = %v", err)
		}
	}()
	sess := node.Session()

	if vendorID, err := basicinformation.VendorID(sess, rootEndpointID); err != nil {
		t.Errorf("basicinformation.VendorID() error = %v", err)
	} else if vendorID != mockRealDeviceQuirksVendorID {
		t.Errorf("basicinformation.VendorID() = 0x%04X, want 0x%04X", vendorID, uint16(mockRealDeviceQuirksVendorID))
	}

	if rebootCount, ok, err := generaldiagnostics.RebootCount(sess, rootEndpointID); err != nil {
		t.Errorf("generaldiagnostics.RebootCount() error = %v", err)
	} else if ok {
		t.Errorf("generaldiagnostics.RebootCount() = (%d, true), want (_, false): this mock device is configured to report it as null", rebootCount)
	}
}
