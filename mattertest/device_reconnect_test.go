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
	"testing"
	"time"

	"github.com/cybergarage/go-matter/matter"
	"github.com/cybergarage/go-matter/matter/cluster/onoff"
	"github.com/cybergarage/go-matter/matter/config"
	"github.com/cybergarage/go-matter/matter/credentials/testcreds"
	"github.com/cybergarage/go-matter/matter/device"
	"github.com/cybergarage/go-matter/matter/device/cluster"
	"github.com/cybergarage/go-matter/matter/encoding"
	"github.com/cybergarage/go-matter/matter/protocol/im"
	"github.com/cybergarage/go-matter/matter/store"
	"github.com/cybergarage/go-matter/matter/types"
)

const reconnectLightDiscriminator = 0x0ABE

// newReconnectLight returns an On/Off Light on st, which a restart keeps.
func newReconnectLight(t *testing.T, st store.DeviceStore) (*device.Device, *cluster.OnOff) {
	t.Helper()
	attestation, err := testcreds.AttestationProvider()
	if err != nil {
		t.Fatal(err)
	}
	dev, err := device.New(
		device.WithDeviceStore(st),
		device.WithPasscode(types.Passcode(deviceCommissioningPasscode)),
		device.WithAddress(":0"),
		device.WithDiscriminator(reconnectLightDiscriminator),
		device.WithVendorID(testcreds.VendorID),
		device.WithProductID(testcreds.ProductID),
		device.WithAttestationProvider(attestation),
	)
	if err != nil {
		t.Fatal(err)
	}
	ep, err := dev.AddEndpoint(1, device.OnOffLightDeviceType)
	if err != nil {
		t.Fatal(err)
	}
	cluster.NewIdentify(cluster.IdentifyTypeLightOutput).Register(ep)
	light := cluster.NewOnOff()
	light.Register(ep)
	return dev, light
}

// TestConnectResumesTheSession commissions an On/Off Light built with
// matter/device and connects to it again and again: the first Connect
// runs a full CASE, the next ones resume the session (4.14.2.2), and a
// subscription follows the node to a new session, both when the node
// reconnects and when the device restarts and forgets the session.
func TestConnectResumesTheSession(t *testing.T) {
	if testing.Short() {
		t.Skip("uses mDNS on the network; skipped with -short")
	}
	deviceStore := store.NewMemDeviceStore()
	dev, _ := newReconnectLight(t, deviceStore)

	mpc := buildManualPairingCodeForTest(t, reconnectLightDiscriminator, deviceCommissioningPasscode, testcreds.VendorID, testcreds.ProductID)
	pairingCode, err := encoding.NewPairingCodeFromString(mpc)
	if err != nil {
		t.Fatal(err)
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
		matter.WithCommissionerAdministratorConfig(adminCfg),
		matter.WithCommissionerOperationalCredentialsConfig(opCfg),
	)
	if err := cmr.Start(); err != nil {
		t.Skipf("the commissioner cannot start here: %v", err)
	}
	defer func() {
		if err := cmr.Stop(); err != nil {
			t.Errorf("Commissioner.Stop() error = %v", err)
		}
	}()
	if err := dev.Start(); err != nil {
		t.Skipf("the device cannot advertise here: %v", err)
	}
	stopped := false
	defer func() {
		if !stopped {
			_ = dev.Stop()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), matter.DefaultCommissioningTimeout)
	defer cancel()
	cme, err := cmr.Commission(ctx, pairingCode, adminCfg, opCfg)
	if err != nil {
		t.Fatalf("Commission() error = %v", err)
	}
	nodeID, _ := cme.NodeID()

	connect := func() (matter.Node, matter.Reconnector) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		node, err := cmr.Connect(ctx, uint64(nodeID))
		if err != nil {
			t.Fatalf("Connect() error = %v", err)
		}
		r, ok := node.(matter.Reconnector)
		if !ok {
			t.Fatal("the node is not a Reconnector")
		}
		if _, err := onoff.OnOff(node.Session(), 1); err != nil {
			t.Fatalf("read OnOff over the session: %v", err)
		}
		return node, r
	}

	first, r := connect()
	if r.Resumed() {
		t.Fatal("the first Connect resumed a session")
	}
	_ = first.Close()
	node, r := connect()
	defer node.Close()
	if !r.Resumed() {
		t.Fatal("the second Connect did not resume the session")
	}

	reports := make(chan *im.Report, 16)
	sub, err := node.(matter.AttributeSubscriber).Subscribe(context.Background(),
		[]im.AttributeRequestPath{im.NewAttributeRequestPath(1, onoff.ClusterID, onoff.OnOffAttributeID)},
		func(r *im.Report) { reports <- r },
		im.WithMaxInterval(2*time.Second),
		im.WithLivenessMargin(2*time.Second))
	if err != nil {
		t.Fatalf("Subscribe() error = %v", err)
	}
	defer sub.Close()
	next := func(what string) *im.Report {
		t.Helper()
		deadline := time.After(60 * time.Second)
		for {
			select {
			case r := <-reports:
				if r.Priming || what != "priming" {
					return r
				}
			case <-deadline:
				t.Fatalf("no %s report", what)
				return nil
			}
		}
	}
	next("priming")

	// Reconnecting resumes again, and the subscription moves over.
	reconnectCtx, cancelReconnect := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelReconnect()
	if err := r.Reconnect(reconnectCtx); err != nil {
		t.Fatalf("Reconnect() error = %v", err)
	}
	if !r.Resumed() {
		t.Error("Reconnect() did not resume the session")
	}
	next("priming")
	resp, err := node.Invoke(1, onoff.ClusterID, onoff.OnCommandID, nil)
	if err != nil || !resp.IsSuccess() {
		t.Fatalf("Invoke(On) after Reconnect() = %+v, %v", resp, err)
	}

	// The device restarts on another port and forgets the session: the
	// subscription gets no answer, and the node reconnects with a full
	// CASE.
	if err := dev.Stop(); err != nil {
		t.Fatal(err)
	}
	stopped = true
	restarted, light := newReconnectLight(t, deviceStore)
	if err := restarted.Start(); err != nil {
		t.Fatalf("restart the device: %v", err)
	}
	defer restarted.Stop()
	next("priming")
	if r.Resumed() {
		t.Error("the node resumed a session the restarted device cannot know")
	}
	light.Set(true)
	for {
		report := next("change")
		if v, ok := onOffIn(report); ok && v {
			break
		}
	}
}

// onOffIn returns the OnOff value of a report.
func onOffIn(r *im.Report) (bool, bool) {
	for _, a := range r.Attributes {
		if a.Path.Attribute == onoff.OnOffAttributeID && a.Value != nil {
			return a.Value.Element.Bool()
		}
	}
	return false, false
}
