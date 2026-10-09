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
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/cybergarage/go-matter/matter"
	"github.com/cybergarage/go-matter/matter/cluster/accesscontrol"
	"github.com/cybergarage/go-matter/matter/cluster/groupkeymanagement"
	"github.com/cybergarage/go-matter/matter/cluster/groups"
	"github.com/cybergarage/go-matter/matter/cluster/onoff"
	"github.com/cybergarage/go-matter/matter/config"
	"github.com/cybergarage/go-matter/matter/credentials/testcreds"
	"github.com/cybergarage/go-matter/matter/device"
	"github.com/cybergarage/go-matter/matter/device/cluster"
	"github.com/cybergarage/go-matter/matter/encoding"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	caseprotocol "github.com/cybergarage/go-matter/matter/protocol/case"
	"github.com/cybergarage/go-matter/matter/protocol/session"
	"github.com/cybergarage/go-matter/matter/store"
	"github.com/cybergarage/go-matter/matter/types"
)

const (
	groupSenderDiscriminator = 0x0ABC
	groupSenderGroupID       = 0x0602
	groupSenderKeySetID      = 0x0042
)

// TestGroupSenderSwitchesDevice commissions an On/Off Light built with
// matter/device, sets up a group on it with the controller's cluster
// clients, and switches it with group messages sent by a
// matter.GroupSender to the group's IPv6 multicast address: a command,
// then an attribute write.
func TestGroupSenderSwitchesDevice(t *testing.T) {
	if testing.Short() {
		t.Skip("uses mDNS and IPv6 multicast on the network; skipped with -short")
	}
	attestation, err := testcreds.AttestationProvider()
	if err != nil {
		t.Fatal(err)
	}
	dev, err := device.New(
		device.WithDeviceStore(store.NewMemDeviceStore()),
		device.WithPasscode(types.Passcode(deviceCommissioningPasscode)),
		device.WithAddress(":0"),
		device.WithDiscriminator(groupSenderDiscriminator),
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
	identify := cluster.NewIdentify(cluster.IdentifyTypeLightOutput)
	identify.Register(ep)
	light := cluster.NewOnOff()
	light.Register(ep)
	cluster.NewGroups(cluster.WithGroupsIdentify(identify)).Register(ep)

	mpc := buildManualPairingCodeForTest(t, groupSenderDiscriminator, deviceCommissioningPasscode, testcreds.VendorID, testcreds.ProductID)
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
	// The device starts after the commissioner's mDNS client, which
	// go-mdns does not let take messages while it starts.
	if err := dev.Start(); err != nil {
		t.Skipf("the device cannot advertise here: %v", err)
	}
	defer func() {
		if err := dev.Stop(); err != nil {
			t.Errorf("Device.Stop() error = %v", err)
		}
	}()
	// The caller deadline bounds discovery and the complete PASE-through-CASE flow.
	ctx, cancel := context.WithTimeout(context.Background(), matter.DefaultCommissioningTimeout)
	defer cancel()
	cme, err := cmr.Commission(ctx, pairingCode, adminCfg, opCfg)
	if err != nil {
		t.Fatalf("Commission() error = %v", err)
	}
	nodeID, _ := cme.NodeID()
	connectCtx, cancelConnect := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelConnect()
	node, err := cmr.Connect(connectCtx, uint64(nodeID))
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer node.Close()
	sess := node.Session()
	// The session retransmits at the intervals the device announced in
	// its Sigma2.
	if got, ok := session.PeerMRPParameters(sess); !ok || got != session.DefaultMRPParameters() {
		t.Fatalf("the CASE session has peer MRP parameters %+v, %v; want the device's %+v", got, ok, session.DefaultMRPParameters())
	}

	// 4.15.3. Group Key Management, 1.3. Groups, 9.10. Access Control:
	// the key set, the group's key, the light's membership and the
	// group's privilege.
	admin, err := caseprotocol.LoadAdministratorMetadata(adminCfg)
	if err != nil {
		t.Fatal(err)
	}
	epochKey := bytes.Repeat([]byte{0x5A}, 16)
	if err := groupkeymanagement.KeySetWrite(sess, groupSenderKeySetID, []groupkeymanagement.EpochKey{{Key: epochKey, StartTime: 1}}); err != nil {
		t.Fatal(err)
	}
	if err := groupkeymanagement.WriteGroupKeyMap(sess, []groupkeymanagement.GroupKeyMapEntry{{GroupID: groupSenderGroupID, GroupKeySetID: groupSenderKeySetID}}); err != nil {
		t.Fatal(err)
	}
	if err := groups.AddGroup(sess, 1, groupSenderGroupID, "Living Room"); err != nil {
		t.Fatal(err)
	}
	if err := accesscontrol.WriteACL(sess, []accesscontrol.Entry{
		{Privilege: accesscontrol.PrivilegeAdminister, AuthMode: accesscontrol.AuthModeCASE, Subjects: []uint64{admin.NodeID}},
		{Privilege: accesscontrol.PrivilegeOperate, AuthMode: accesscontrol.AuthModeGroup, Subjects: []uint64{groupSenderGroupID}},
	}); err != nil {
		t.Fatal(err)
	}

	sender, err := matter.NewGroupSender(adminCfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := sender.Invoke(groupSenderGroupID, epochKey, onoff.ClusterID, onoff.OnCommandID, nil); err != nil {
		t.Skipf("no IPv6 multicast here: %v", err)
	}
	waitUntil(t, "the group's On command to turn the light on", light.On)
	if err := sender.WriteAttribute(groupSenderGroupID, epochKey, onoff.ClusterID, cluster.OnTimeAttributeID, func(enc tlv.Encoder) error {
		enc.PutUnsigned2(tlv.NewContextTag(2), 240)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "the group's write to set OnTime", func() bool {
		resp, err := node.ReadAttribute(1, onoff.ClusterID, cluster.OnTimeAttributeID)
		if err != nil || resp.Value == nil {
			return false
		}
		v, ok := resp.Value.Unsigned()
		return ok && v == 240
	})
	if err := sender.Invoke(groupSenderGroupID, epochKey, onoff.ClusterID, onoff.OffCommandID, nil); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "the group's Off command to turn the light off", func() bool { return !light.On() })
}

// waitUntil polls cond for up to five seconds.
func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
