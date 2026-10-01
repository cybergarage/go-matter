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

package device

import (
	"bytes"
	"context"
	"net"
	"sync/atomic"
	"testing"

	"github.com/cybergarage/go-matter/matter/cluster/accesscontrol"
	"github.com/cybergarage/go-matter/matter/cluster/groupkeymanagement"
	"github.com/cybergarage/go-matter/matter/cluster/groups"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	caseprotocol "github.com/cybergarage/go-matter/matter/protocol/case"
	"github.com/cybergarage/go-matter/matter/protocol/group"
	"github.com/cybergarage/go-matter/matter/protocol/im"
)

// TestGroupSender has a controller set up a group on the device with the
// cluster clients, and command and write it with a group.Sender.
func TestGroupSender(t *testing.T) {
	d, adv, _, client, admin := commissionedDevice(t)
	waitOperational(t, adv, 1)
	ep, err := d.AddEndpoint(1, OnOffLightDeviceType)
	if err != nil {
		t.Fatal(err)
	}
	var on, onTime atomic.Uint32
	ep.HandleCommand(0x0006, 0x01, func(*im.CommandRequest) im.CommandResult {
		on.Add(1)
		return im.CommandStatus(im.StatusSuccess)
	})
	ep.HandleAttribute(0x0006, 0x4001, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		enc.PutUnsigned2(tag, uint16(onTime.Load())) // nolint: gosec // set from a uint16
		return im.StatusSuccess
	})
	ep.HandleAttributeWrite(0x0006, 0x4001, func(req *im.AttributeWriteRequest) im.Status {
		_, elem, err := req.Decoder()
		if err != nil {
			return im.StatusInvalidDataType
		}
		v, _ := elem.Unsigned()
		onTime.Store(uint32(v)) // nolint: gosec // a uint16
		return im.StatusSuccess
	})
	// The device's Groups cluster is the application's; this test puts
	// the endpoint in the group as a Groups AddGroup would.
	ep.HandleCommand(groups.ClusterID, groups.AddGroupCommandID, func(req *im.CommandRequest) im.CommandResult {
		id, _ := req.Fields[0].Unsigned()
		name, _ := req.Fields[1].UTF8()
		status := ep.JoinGroup(ep.AccessingFabric(req.Session), uint16(id), name) // nolint: gosec // a group ID
		enc := tlv.NewEncoder()
		enc.BeginStructure(tlv.NewContextTag(1))
		enc.PutUnsigned1(tlv.NewContextTag(0), uint8(status))
		enc.PutUnsigned2(tlv.NewContextTag(1), uint16(id)) // nolint: gosec // a group ID
		_ = enc.EndContainer()
		return im.CommandResponse(groups.AddGroupCommandID, enc.Bytes())
	})

	const groupID = 0x0601
	epochKey := bytes.Repeat([]byte{0xA5}, 16)
	if err := groupkeymanagement.KeySetWrite(admin, 7, []groupkeymanagement.EpochKey{{Key: epochKey, StartTime: 1}}); err != nil {
		t.Fatal(err)
	}
	if err := groupkeymanagement.WriteGroupKeyMap(admin, []groupkeymanagement.GroupKeyMapEntry{{GroupID: groupID, GroupKeySetID: 7}}); err != nil {
		t.Fatal(err)
	}
	if err := groups.AddGroup(admin, 1, groupID, "Kitchen"); err != nil {
		t.Fatal(err)
	}
	if err := accesscontrol.WriteACL(admin, []accesscontrol.Entry{
		{Privilege: accesscontrol.PrivilegeAdminister, AuthMode: accesscontrol.AuthModeCASE, Subjects: []uint64{testAdminNodeID}},
		{Privilege: accesscontrol.PrivilegeOperate, AuthMode: accesscontrol.AuthModeGroup, Subjects: []uint64{groupID}},
	}); err != nil {
		t.Fatal(err)
	}

	fabrics, err := d.store.ListDeviceFabrics()
	if err != nil || len(fabrics) != 1 {
		t.Fatal(fabrics, err)
	}
	cfid, err := caseprotocol.ComputeCompressedFabricID(fabrics[0].RootPublicKey, fabrics[0].FabricID)
	if err != nil {
		t.Fatal(err)
	}
	// The sender's messages go to the device's unicast address here, as
	// the host may not route IPv6 multicast; mattertest sends them to the
	// group's address.
	var sentTo *net.UDPAddr
	sender, err := group.NewSender(fabrics[0].FabricID, cfid, testAdminNodeID, group.WithTransmitter(func(addr *net.UDPAddr, packet []byte) error {
		sentTo = addr
		return client.Transmit(context.Background(), packet)
	}))
	if err != nil {
		t.Fatal(err)
	}
	if err := sender.Invoke(groupID, epochKey, 0x0006, 0x01, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the group command to run", func() bool { return on.Load() == 1 })
	if !sentTo.IP.Equal(group.MulticastAddress(fabrics[0].FabricID, groupID)) || sentTo.Port != group.Port {
		t.Fatalf("the sender sent to %v, want the group's address", sentTo)
	}
	if err := sender.WriteAttribute(groupID, epochKey, 0x0006, 0x4001, func(enc tlv.Encoder) error {
		enc.PutUnsigned2(tlv.NewContextTag(2), 120)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the group write to set OnTime", func() bool { return onTime.Load() == 120 })
	if err := sender.Invoke(0, epochKey, 0x0006, 0x01, nil); err == nil {
		t.Fatal("a message to group 0 was sent")
	}
}
