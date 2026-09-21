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
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter"
	"github.com/cybergarage/go-matter/matter/ble"
	"github.com/cybergarage/go-matter/matter/cluster/accesscontrol"
	"github.com/cybergarage/go-matter/matter/cluster/basicinformation"
	"github.com/cybergarage/go-matter/matter/cluster/descriptor"
	"github.com/cybergarage/go-matter/matter/cluster/generaldiagnostics"
	"github.com/cybergarage/go-matter/matter/config"
	"github.com/cybergarage/go-matter/matter/encoding"
	"github.com/cybergarage/go-matter/matter/protocol/im"
	"github.com/cybergarage/go-matter/mattertest/mockdevice"
)

// rootEndpointID is the Root Node endpoint (0) every attribute read in this
// test targets.
const rootEndpointID im.EndpointID = 0

// noopBLECentral is a matter.WithCommissionerCentral override that never
// touches real Bluetooth hardware: this test commissions over UDP only
// (like TestMockCommissioning), via the fake mDNS discoverer passed to
// WithCommissionerDiscoverer, so BLE scanning has nothing to contribute —
// letting Discover/Commission fall through to a real ble.Central here would
// only add a redundant, real-hardware-touching Enable/Scan/Disable cycle
// that has proven unreliable when several mock-device tests in this package
// run BLE centrals back to back in the same process (each of
// TestMockCommissioning/TestMockBLECommissioning already does this, and a
// third one — this test — reproducibly hit go-ble's "already calling
// Enable function" guard).
type noopBLECentral struct{}

func (noopBLECentral) DiscoveredDevices() []ble.Device { return nil }

func (noopBLECentral) LookupDeviceByDiscriminator(_ any) (ble.Device, error) {
	return nil, fmt.Errorf("noopBLECentral: no BLE device")
}

func (noopBLECentral) Scan(_ context.Context, _ ...ble.ScannerOption) error { return nil }

// mockBasicOperationsDeviceTypeID is the Root Node device type
// (matter/cluster/descriptor's DeviceType field) mockdevice's Descriptor
// cluster reports for endpoint 0, per the Device Library's Root Node
// device type definition.
const mockBasicOperationsDeviceTypeID uint32 = 0x0016

// mockBasicOperationsDiscriminator/.../ProductID are a synthetic identity
// for this test's mock device, distinct from TestMockCommissioning's
// (0xFFF1/0x8001) and TestMockBLECommissioning's (0xFFF2/0x8002) — no two
// mock-device tests in this package should share an MPC identity.
const (
	mockBasicOperationsDiscriminator = 0x0BB0
	mockBasicOperationsPasscode      = 20202022
	mockBasicOperationsVendorID      = 0xFFF1
	mockBasicOperationsProductID     = 0x8003
)

// TestMockBasicOperations commissions an entirely in-process mockdevice.Device
// (like TestMockCommissioning), then — unlike every other mock-device test in
// this package, which only asserts persisted-store state — reconnects to the
// freshly commissioned node via Commissioner.Connect (a fresh CASE handshake;
// Commission's own CASE session is already closed by the time it returns,
// see commissioning_impl.go's finalizeCommissioningOverCASE) and reads
// attributes from every mandatory Root-Node cluster this repo has a client
// for: Descriptor, Basic Information, Access Control and General
// Diagnostics. This is the first end-to-end test proving the Interaction
// Model client stack (matter/protocol/im, matter/cluster/*) works
// operationally, not just during the commissioning handshake itself.
func TestMockBasicOperations(t *testing.T) {
	log.EnableStdoutDebug(true)
	defer log.EnableStdoutDebug(false)

	dev, err := mockdevice.New(
		mockdevice.WithDiscriminator(mockBasicOperationsDiscriminator),
		mockdevice.WithPasscode(mockBasicOperationsPasscode),
		mockdevice.WithVendorID(mockBasicOperationsVendorID),
		mockdevice.WithProductID(mockBasicOperationsProductID),
	)
	if err != nil {
		t.Fatalf("mockdevice.New() error = %v", err)
	}
	if err := dev.Start(); err != nil {
		t.Fatalf("Device.Start() error = %v", err)
	}
	defer func() {
		if err := dev.Stop(); err != nil {
			t.Errorf("Device.Stop() error = %v", err)
		}
	}()

	mpc := buildManualPairingCodeForTest(t, mockBasicOperationsDiscriminator, mockBasicOperationsPasscode, mockBasicOperationsVendorID, mockBasicOperationsProductID)
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

	// Connect (unlike Commission) has no explicit adminCfg/opCfg parameters
	// of its own — it reuses the Commissioner's own fabric identity, so
	// that identity must be supplied here, at construction, not just
	// passed to Commission below.
	storeDir := t.TempDir()
	cmr := matter.NewCommissioner(
		matter.WithCommissionerDiscoverer(mockdevice.NewFakeDiscoverer(dev)),
		matter.WithCommissionerCentral(noopBLECentral{}),
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

	// See TestMockCommissioning's matching comment: the fake discoverer
	// answers immediately, so a short deadline is enough for discovery; the
	// commissioning phase itself is governed by
	// matter.DefaultCommissioningTimeout, not this ctx.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cme, err := cmr.Commission(ctx, pairingCode, adminCfg, opCfg)
	if err != nil {
		t.Fatalf("Failed to commission mock device: %v", err)
	}
	t.Logf("Successfully commissioned mock device: %s", cme.String())

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

	// Descriptor (0x001D) — mandatory on every endpoint.
	deviceTypes, err := descriptor.DeviceTypeList(sess, rootEndpointID)
	if err != nil {
		t.Fatalf("descriptor.DeviceTypeList() error = %v", err)
	}
	if !slices.ContainsFunc(deviceTypes, func(dt descriptor.DeviceType) bool { return dt.DeviceType == mockBasicOperationsDeviceTypeID }) {
		t.Errorf("descriptor.DeviceTypeList() = %+v, want it to contain the Root Node device type 0x%04X", deviceTypes, mockBasicOperationsDeviceTypeID)
	}

	servers, err := descriptor.ServerList(sess, rootEndpointID)
	if err != nil {
		t.Fatalf("descriptor.ServerList() error = %v", err)
	}
	for _, want := range []im.ClusterID{descriptor.ClusterID, basicinformation.ClusterID, accesscontrol.ClusterID, generaldiagnostics.ClusterID} {
		if !slices.Contains(servers, want) {
			t.Errorf("descriptor.ServerList() = %v, want it to contain cluster 0x%04X", servers, want)
		}
	}

	if clients, err := descriptor.ClientList(sess, rootEndpointID); err != nil {
		t.Errorf("descriptor.ClientList() error = %v", err)
	} else if len(clients) != 0 {
		t.Errorf("descriptor.ClientList() = %v, want empty", clients)
	}

	if parts, err := descriptor.PartsList(sess, rootEndpointID); err != nil {
		t.Errorf("descriptor.PartsList() error = %v", err)
	} else if len(parts) != 0 {
		t.Errorf("descriptor.PartsList() = %v, want empty", parts)
	}

	// Basic Information (0x0028) — mandatory on endpoint 0.
	if vendorID, err := basicinformation.VendorID(sess, rootEndpointID); err != nil {
		t.Errorf("basicinformation.VendorID() error = %v", err)
	} else if vendorID != mockBasicOperationsVendorID {
		t.Errorf("basicinformation.VendorID() = 0x%04X, want 0x%04X", vendorID, uint16(mockBasicOperationsVendorID))
	}

	if productID, err := basicinformation.ProductID(sess, rootEndpointID); err != nil {
		t.Errorf("basicinformation.ProductID() error = %v", err)
	} else if productID != mockBasicOperationsProductID {
		t.Errorf("basicinformation.ProductID() = 0x%04X, want 0x%04X", productID, uint16(mockBasicOperationsProductID))
	}

	// Access Control (0x001F) — mandatory on endpoint 0.
	if entries, err := accesscontrol.AccessControlEntriesPerFabric(sess, rootEndpointID); err != nil {
		t.Errorf("accesscontrol.AccessControlEntriesPerFabric() error = %v", err)
	} else if entries == 0 {
		t.Errorf("accesscontrol.AccessControlEntriesPerFabric() = 0, want a positive spec-mandated minimum")
	}

	// General Diagnostics (0x0033) — mandatory on endpoint 0.
	if _, err := generaldiagnostics.RebootCount(sess, rootEndpointID); err != nil {
		t.Errorf("generaldiagnostics.RebootCount() error = %v", err)
	}
}
