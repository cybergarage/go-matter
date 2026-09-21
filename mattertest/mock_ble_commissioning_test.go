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
	"github.com/cybergarage/go-matter/matter/config"
	"github.com/cybergarage/go-matter/matter/encoding"
	"github.com/cybergarage/go-matter/mattertest/mockdevice"
)

// mockBLECommissioningDiscriminator/.../ProductID are a synthetic identity
// for this test's simulated BLE peripheral, distinct from both any real
// device's actual values and from mock_commissioning_test.go's own UDP-mode
// identity (confirmed with the user: the MPC used here must not be a real
// device's — see mock_commissioning_test.go's matching comment).
const (
	mockBLECommissioningDiscriminator = 0x0DEF
	mockBLECommissioningPasscode      = 10101011
	mockBLECommissioningVendorID      = 0xFFF2
	mockBLECommissioningProductID     = 0x8002
)

// TestMockBLECommissioning commissions an entirely in-process simulated BLE
// peripheral (mockdevice.NewFakeBLECentral), the BLE counterpart to
// TestMockCommissioning's UDP-only one: it exercises matter/ble's real
// scanning, GATT characteristic lookup, BTP handshake (including the
// write-before-subscribe ordering matter/ble/transport.go's Handshake
// depends on) and BTP data-segment framing/reassembly
// (matter/ble/btp/segment.go) code, none of which TestMockCommissioning's
// UDP-only mock ever runs — every one of those was a real, only-reproduced-
// against-hardware bug this project's history fixed, so this is the
// regression test none of them had before.
func TestMockBLECommissioning(t *testing.T) {
	log.EnableStdoutDebug(true)
	defer log.EnableStdoutDebug(false)

	dev, err := mockdevice.New(
		mockdevice.WithDiscriminator(mockBLECommissioningDiscriminator),
		mockdevice.WithPasscode(mockBLECommissioningPasscode),
		mockdevice.WithVendorID(mockBLECommissioningVendorID),
		mockdevice.WithProductID(mockBLECommissioningProductID),
	)
	if err != nil {
		t.Fatalf("mockdevice.New() error = %v", err)
	}

	central, handshakeObserver, err := mockdevice.NewFakeBLECentral(dev)
	if err != nil {
		t.Fatalf("mockdevice.NewFakeBLECentral() error = %v", err)
	}
	defer func() {
		if err := dev.Stop(); err != nil {
			t.Errorf("Device.Stop() error = %v", err)
		}
	}()

	mpc := buildManualPairingCodeForTest(t, mockBLECommissioningDiscriminator, mockBLECommissioningPasscode, mockBLECommissioningVendorID, mockBLECommissioningProductID)
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
	// The BLE transport unconditionally requires Wi-Fi network config
	// (matter/device_ble.go's Commission passes requireNetwork=true to
	// commissionNetwork) — mockdevice's registerNetworkCommissioningHandlers
	// answers AddOrUpdateWiFiNetwork/ConnectNetwork with success regardless
	// of what's actually sent, so these values only need to be non-empty.
	wifiCfg := config.NewWiFiNetworkConfig(
		config.WithSSID([]byte("mock-ssid")),
		config.WithCredentials([]byte("mock-password")),
	)

	storeDir := t.TempDir()
	cmr := matter.NewCommissioner(
		matter.WithCommissionerCentral(central),
		matter.WithCommissionerDiscoverer(mockdevice.NewFakeOperationalDiscoverer(dev)),
		matter.WithCommissionerStoreDir(storeDir),
	)
	if err := cmr.Start(); err != nil {
		t.Fatalf("Commissioner.Start() error = %v", err)
	}
	defer func() {
		if err := cmr.Stop(); err != nil {
			t.Errorf("Commissioner.Stop() error = %v", err)
		}
	}()

	// See mock_commissioning_test.go's matching comment: the fake central
	// answers Scan immediately, so a short deadline is enough for
	// discovery; the commissioning phase that follows is governed by
	// matter.DefaultCommissioningTimeout, not this ctx.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cme, err := cmr.Commission(ctx, pairingCode, adminCfg, opCfg, wifiCfg)
	if err != nil {
		t.Fatalf("Failed to commission simulated BLE device: %v", err)
	}
	t.Logf("Successfully commissioned simulated BLE device: %s", cme.String())

	select {
	case <-dev.CommissioningCompleted():
	case <-time.After(1 * time.Second):
		t.Error("Device.CommissioningCompleted() did not fire after Commission() returned success")
	}

	orderCtx, orderCancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer orderCancel()
	orderOK, err := handshakeObserver.HandshakeOrderOK(orderCtx)
	if err != nil {
		t.Fatalf("HandshakeOrderOK() error = %v", err)
	}
	if !orderOK {
		t.Error("HandshakeOrderOK() = false: the BTP handshake request was written after Subscribe was called, " +
			"not before it — matter/ble/transport.go's Handshake regressed to the order a real device never responds to")
	}
}
