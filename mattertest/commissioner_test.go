// Copyright (C) 2024 The go-matter Authors. All rights reserved.
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
	"slices"
	"testing"
	"time"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter"
	"github.com/cybergarage/go-matter/matter/cluster/accesscontrol"
	"github.com/cybergarage/go-matter/matter/cluster/basicinformation"
	"github.com/cybergarage/go-matter/matter/cluster/descriptor"
	"github.com/cybergarage/go-matter/matter/cluster/generaldiagnostics"
	"github.com/cybergarage/go-matter/matter/protocol/im"
)

// liveRootEndpointID is the Root Node endpoint (0) every post-commissioning
// attribute read below targets.
const liveRootEndpointID im.EndpointID = 0

func TestCommissioner(t *testing.T) {
	t.Helper()

	scenario, err := loadLiveCommissioningScenarioFromEnv()
	if errors.Is(err, errLiveCommissioningDisabled) {
		t.Skip("live commissioner interop disabled; set MATTER_TEST_COMMISSIONER_LIVE=1 to enable")
	}
	if err != nil {
		t.Fatalf("loadLiveCommissioningScenarioFromEnv() error = %v", err)
	}

	log.EnableStdoutDebug(true)
	defer log.EnableStdoutDebug(false)

	// WithCommissionerAdministratorConfig/WithCommissionerOperationalCredentialsConfig
	// are required here, not just passed to Commission below: Connect (used
	// by verifyLiveBasicOperations after commissioning) resolves the fabric
	// identity from the commissioner's own fields, which are otherwise left
	// nil (see commissioner_impl.go's Connect: "no fabric identity
	// available").
	cmr := matter.NewCommissioner(
		matter.WithCommissionerStoreDir(t.TempDir()),
		matter.WithCommissionerAdministratorConfig(scenario.Admin),
		matter.WithCommissionerOperationalCredentialsConfig(scenario.Operational),
	)
	if err := cmr.Start(); err != nil {
		t.Fatalf("Failed to start commissioner: %v", err)
	}
	defer func() {
		if err := cmr.Stop(); err != nil {
			t.Errorf("Failed to stop commissioner: %v", err)
		}
	}()

	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: scenario.Name,
			run: func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
				defer cancel()

				opts := scenario.Options()
				cme, err := cmr.Commission(ctx, scenario.PairingCode, opts...)
				if err != nil {
					t.Fatalf("Failed to commission device: %v", err)
				}
				t.Logf("Successfully commissioned device: %s", cme.String())

				nodeID, ok := cme.NodeID()
				if !ok {
					t.Fatal("Commissionee.NodeID() ok = false after successful commissioning")
				}
				verifyLiveBasicOperations(t, cmr, nodeID)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, tt.run)
	}
}

// verifyLiveBasicOperations reconnects to nodeID via a fresh CASE handshake
// (Commission's own CASE session is already closed by the time it returns —
// see commissioning_impl.go's finalizeCommissioningOverCASE) and reads
// attributes from every mandatory Root-Node cluster this repo has a client
// for: Descriptor, Basic Information, Access Control and General
// Diagnostics. This mirrors mock_basic_operations_test.go's
// TestMockBasicOperations, but against the real device scenario just
// commissioned above — the actual proof that the Interaction Model client
// stack (matter/protocol/im, matter/cluster/*) interoperates with real
// hardware, not just this project's own mock. Failures are reported with
// t.Errorf, not t.Fatalf, so one cluster's failure doesn't hide the rest.
func verifyLiveBasicOperations(t *testing.T, cmr matter.Commissioner, nodeID matter.NodeID) {
	t.Helper()

	connectCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	node, err := cmr.Connect(connectCtx, uint64(nodeID))
	if err != nil {
		t.Errorf("Commissioner.Connect() error = %v", err)
		return
	}
	defer func() {
		if err := node.Close(); err != nil {
			t.Errorf("Node.Close() error = %v", err)
		}
	}()
	sess := node.Session()

	// Descriptor (0x001D) — mandatory on every endpoint.
	if deviceTypes, err := descriptor.DeviceTypeList(sess, liveRootEndpointID); err != nil {
		t.Errorf("descriptor.DeviceTypeList() error = %v", err)
	} else {
		t.Logf("descriptor.DeviceTypeList() = %+v", deviceTypes)
		if len(deviceTypes) == 0 {
			t.Error("descriptor.DeviceTypeList() = [], want at least one device type")
		}
	}

	if servers, err := descriptor.ServerList(sess, liveRootEndpointID); err != nil {
		t.Errorf("descriptor.ServerList() error = %v", err)
	} else {
		t.Logf("descriptor.ServerList() = %v", servers)
		// A device's own Descriptor/Basic Information cluster IDs are
		// self-referential — any spec-compliant Root Node must list them.
		for _, want := range []im.ClusterID{descriptor.ClusterID, basicinformation.ClusterID} {
			if !slices.Contains(servers, want) {
				t.Errorf("descriptor.ServerList() = %v, want it to contain cluster 0x%04X", servers, want)
			}
		}
	}

	// Basic Information (0x0028) — mandatory on endpoint 0. No expected
	// value to assert against (unlike the mock, a real device's identity
	// isn't known in advance) — just confirm the read itself succeeds.
	if vendorID, err := basicinformation.VendorID(sess, liveRootEndpointID); err != nil {
		t.Errorf("basicinformation.VendorID() error = %v", err)
	} else {
		t.Logf("basicinformation.VendorID() = 0x%04X", vendorID)
	}
	if productID, err := basicinformation.ProductID(sess, liveRootEndpointID); err != nil {
		t.Errorf("basicinformation.ProductID() error = %v", err)
	} else {
		t.Logf("basicinformation.ProductID() = 0x%04X", productID)
	}

	// Access Control (0x001F) — mandatory on endpoint 0.
	if entries, err := accesscontrol.AccessControlEntriesPerFabric(sess, liveRootEndpointID); err != nil {
		t.Errorf("accesscontrol.AccessControlEntriesPerFabric() error = %v", err)
	} else {
		t.Logf("accesscontrol.AccessControlEntriesPerFabric() = %d", entries)
	}

	// General Diagnostics (0x0033) — mandatory on endpoint 0.
	if rebootCount, err := generaldiagnostics.RebootCount(sess, liveRootEndpointID); err != nil {
		t.Errorf("generaldiagnostics.RebootCount() error = %v", err)
	} else {
		t.Logf("generaldiagnostics.RebootCount() = %d", rebootCount)
	}
}
