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
	"time"

	"github.com/cybergarage/go-matter/matter/encoding/message"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	caseprotocol "github.com/cybergarage/go-matter/matter/protocol/case"
	"github.com/cybergarage/go-matter/matter/protocol/group"
	"github.com/cybergarage/go-matter/matter/protocol/im"
	"github.com/cybergarage/go-matter/matter/store"
)

func TestGroupCounterWindow(t *testing.T) {
	w := &groupCounterWindow{max: 10, window: 0}
	for _, tc := range []struct {
		counter uint32
		want    bool
	}{
		{10, false}, {11, true}, {11, false}, {9, true}, {9, false},
		{50, true}, {20, true}, {17, false}, {18, true}, {18, false},
	} {
		if got := w.accept(tc.counter); got != tc.want {
			t.Errorf("accept(%d) = %v, want %v", tc.counter, got, tc.want)
		}
	}
}

// groupInvoke encodes a group message's InvokeRequest of a command which
// names no endpoint.
func groupInvoke(t *testing.T, cluster im.ClusterID, command im.CommandID) []byte {
	t.Helper()
	hdr, err := message.NewProtocolHeader(
		message.WithHeaderExchangeFlags(message.InitiatorFlag),
		message.WithHeaderOpcode(message.InvokeRequestMessage),
		message.WithHeaderExchangeID(0x1234),
		message.WithHeaderProtocolID(message.InteractionModel),
	).Bytes()
	if err != nil {
		t.Fatal(err)
	}
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	enc.PutBool(tlv.NewContextTag(0), true)
	enc.PutBool(tlv.NewContextTag(1), false)
	enc.BeginArray(tlv.NewContextTag(2))
	enc.BeginStructure(tlv.NewAnonymousTag())
	enc.BeginList(tlv.NewContextTag(0))
	enc.PutUnsigned4(tlv.NewContextTag(1), uint32(cluster))
	enc.PutUnsigned4(tlv.NewContextTag(2), uint32(command))
	_ = enc.EndContainer()
	enc.BeginStructure(tlv.NewContextTag(1))
	_ = enc.EndContainer()
	_ = enc.EndContainer()
	_ = enc.EndContainer()
	enc.PutUnsigned1(tlv.NewContextTag(0xFF), 12)
	if err := enc.EndContainer(); err != nil {
		t.Fatal(err)
	}
	return append(hdr, enc.Bytes()...)
}

func TestGroupMessaging(t *testing.T) {
	d, adv, _, client, admin := commissionedDevice(t)
	waitOperational(t, adv, 1)

	// Group 0x0101 of the fabric uses key set 42, and members may Operate.
	epochKey := bytes.Repeat([]byte{0xD0}, epochKeyLength)
	if err := d.store.SaveGroupKeys(1, func() store.GroupKeysRecord {
		rec, _ := d.store.LoadGroupKeys(1)
		rec.KeySets = append(rec.KeySets, store.GroupKeySet{GroupKeySetID: 42, SecurityPolicy: 0, EpochKeys: []store.EpochKey{{Key: epochKey, StartTime: 1}}})
		rec.KeyMap = []store.GroupKeyMapEntry{{GroupID: 0x0101, GroupKeySetID: 42}}
		return rec
	}()); err != nil {
		t.Fatal(err)
	}
	ep, err := d.AddEndpoint(1, OnOffLightDeviceType)
	if err != nil {
		t.Fatal(err)
	}
	var on atomic.Int32
	ep.HandleCommand(0x0006, 0x01, func(req *im.CommandRequest) im.CommandResult {
		if req.Endpoint != 1 {
			t.Errorf("the command ran on endpoint %d", req.Endpoint)
		}
		on.Add(1)
		return im.CommandStatus(im.StatusSuccess)
	})
	if s := ep.JoinGroup(1, 0x0101, "Kitchen"); s != im.StatusSuccess {
		t.Fatalf("JoinGroup: status %#x", uint8(s))
	}

	fabrics, err := d.store.ListDeviceFabrics()
	if err != nil || len(fabrics) != 1 {
		t.Fatal(fabrics, err)
	}
	cfid, err := caseprotocol.ComputeCompressedFabricID(fabrics[0].RootPublicKey, fabrics[0].FabricID)
	if err != nil {
		t.Fatal(err)
	}
	key, err := group.OperationalKey(epochKey, cfid)
	if err != nil {
		t.Fatal(err)
	}
	send := func(counter uint32) {
		t.Helper()
		packet, err := group.Encrypt(key, testAdminNodeID, 0x0101, counter, groupInvoke(t, 0x0006, 0x01))
		if err != nil {
			t.Fatal(err)
		}
		if err := client.Transmit(context.Background(), packet); err != nil {
			t.Fatal(err)
		}
	}
	settle := func() { time.Sleep(100 * time.Millisecond) }

	// Without a Group ACL entry, the command is not run.
	send(100)
	settle()
	if n := on.Load(); n != 0 {
		t.Fatalf("the command ran %d times without access", n)
	}
	if s := writeACL(t, admin,
		aclEntryFields{uint8(store.PrivilegeAdminister), uint8(store.AuthModeCASE), []uint64{testAdminNodeID}, nil},
		aclEntryFields{uint8(store.PrivilegeOperate), uint8(store.AuthModeGroup), []uint64{0x0101}, nil},
	); s != im.StatusSuccess {
		t.Fatalf("write ACL: status %#x", uint8(s))
	}
	send(101)
	settle()
	if n := on.Load(); n != 1 {
		t.Fatalf("the group command ran %d times, want once", n)
	}
	// A replay is dropped, a message to another group or under another
	// key is not decrypted.
	send(101)
	other, _ := group.Encrypt(key, testAdminNodeID, 0x0202, 102, groupInvoke(t, 0x0006, 0x01))
	_ = client.Transmit(context.Background(), other)
	wrongKey, _ := group.OperationalKey(bytes.Repeat([]byte{0xD1}, epochKeyLength), cfid)
	wrong, _ := group.Encrypt(wrongKey, testAdminNodeID, 0x0101, 103, groupInvoke(t, 0x0006, 0x01))
	_ = client.Transmit(context.Background(), wrong)
	settle()
	if n := on.Load(); n != 1 {
		t.Fatalf("the group command ran %d times, want only once", n)
	}
	// On a host with IPv6 multicast, the device listens on the group's
	// address, where a group message reaches it.
	addr := &net.UDPAddr{IP: group.MulticastAddress(fabrics[0].FabricID, 0x0101), Port: group.Port, Zone: ""}
	if probe, err := listenGroup(addr.IP); err != nil {
		t.Logf("no IPv6 multicast here (%v): the group's address is not checked", err)
	} else {
		_ = probe.Close()
		waitFor(t, "the device to listen on the group's address", func() bool { return d.groups.joined(addr.IP) })
		if conn, err := net.DialUDP("udp6", nil, addr); err == nil {
			packet, _ := group.Encrypt(key, testAdminNodeID, 0x0101, 105, groupInvoke(t, 0x0006, 0x01))
			if _, err := conn.Write(packet); err == nil {
				deadline := time.Now().Add(time.Second)
				for on.Load() != 2 && time.Now().Before(deadline) {
					time.Sleep(10 * time.Millisecond)
				}
				t.Logf("a group message sent to %s ran the command %d times in all", addr.IP, on.Load())
			}
			_ = conn.Close()
		}
		on.Store(1)
	}

	// The endpoint which left the group is not reached.
	ep.LeaveGroup(1, 0x0101)
	send(106)
	settle()
	if n := on.Load(); n != 1 {
		t.Fatalf("the command reached an endpoint out of the group (%d runs)", n)
	}
}
