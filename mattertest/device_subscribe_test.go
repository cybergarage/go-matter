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

const subscribeLightDiscriminator = 0x0ABD

// TestSubscribeToDevice commissions an On/Off Light built with
// matter/device, connects to it with a short deadline, and subscribes to
// its OnOff attribute: the priming report, a change made with Toggle on
// the same node, and a change made on the device after the connect
// deadline has passed, which the node's session outlives.
func TestSubscribeToDevice(t *testing.T) {
	if testing.Short() {
		t.Skip("uses mDNS on the network; skipped with -short")
	}
	attestation, err := testcreds.AttestationProvider()
	if err != nil {
		t.Fatal(err)
	}
	dev, err := device.New(
		device.WithDeviceStore(store.NewMemDeviceStore()),
		device.WithPasscode(types.Passcode(deviceCommissioningPasscode)),
		device.WithAddress(":0"),
		device.WithDiscriminator(subscribeLightDiscriminator),
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

	mpc := buildManualPairingCodeForTest(t, subscribeLightDiscriminator, deviceCommissioningPasscode, testcreds.VendorID, testcreds.ProductID)
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
	defer func() {
		if err := dev.Stop(); err != nil {
			t.Errorf("Device.Stop() error = %v", err)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), matter.DefaultCommissioningTimeout)
	defer cancel()
	cme, err := cmr.Commission(ctx, pairingCode, adminCfg, opCfg)
	if err != nil {
		t.Fatalf("Commission() error = %v", err)
	}
	nodeID, _ := cme.NodeID()

	const connectTimeout = 10 * time.Second
	connectCtx, cancelConnect := context.WithTimeout(context.Background(), connectTimeout)
	defer cancelConnect()
	connectDeadline, _ := connectCtx.Deadline()
	node, err := cmr.Connect(connectCtx, uint64(nodeID))
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer node.Close()
	subscriber, ok := node.(matter.AttributeSubscriber)
	if !ok {
		t.Fatal("the node is not an AttributeSubscriber")
	}

	reports := make(chan *im.Report, 8)
	sub, err := subscriber.Subscribe(context.Background(),
		[]im.AttributeRequestPath{im.NewAttributeRequestPath(1, onoff.ClusterID, onoff.OnOffAttributeID)},
		func(r *im.Report) { reports <- r },
		im.WithMaxInterval(30*time.Second))
	if err != nil {
		t.Fatalf("Subscribe() error = %v", err)
	}
	defer sub.Close()

	next := func() bool {
		t.Helper()
		select {
		case r := <-reports:
			for _, a := range r.Attributes {
				if a.Path.Attribute == onoff.OnOffAttributeID && a.Value != nil {
					v, _ := a.Value.Element.Bool()
					return v
				}
			}
			t.Fatalf("the report has no OnOff value: %+v", r.Attributes)
		case <-time.After(10 * time.Second):
			t.Fatal("no report")
		}
		return false
	}
	if next() {
		t.Fatal("the priming report has OnOff true, want false")
	}

	// Toggle on the node which holds the subscription.
	resp, err := node.Invoke(1, onoff.ClusterID, onoff.ToggleCommandID, nil)
	if err != nil || !resp.IsSuccess() {
		t.Fatalf("Invoke(Toggle) = %+v, %v", resp, err)
	}
	if !next() {
		t.Fatal("the report after Toggle has OnOff false")
	}

	// The node's session outlives the deadline it was connected with.
	time.Sleep(time.Until(connectDeadline) + time.Second)
	light.Set(false)
	if next() {
		t.Fatal("the report after the device switched off has OnOff true")
	}
	v, err := onoff.OnOff(node.Session(), 1)
	if err != nil || v {
		t.Fatalf("onoff.OnOff() after the connect deadline = %v, %v; want false", v, err)
	}
}
