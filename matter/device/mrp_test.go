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
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cybergarage/go-matter/matter/encoding/message"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	caseprotocol "github.com/cybergarage/go-matter/matter/protocol/case"
	"github.com/cybergarage/go-matter/matter/protocol/im"
	"github.com/cybergarage/go-matter/matter/protocol/session"
)

// standaloneAckSize bounds the size of an encrypted standalone MRP ack: a
// message header with no node IDs, a protocol header with an ack counter,
// and the MIC.
const standaloneAckSize = 40

// lossyClient is a udpClient which drops the packets from the device that
// drop selects.
type lossyClient struct {
	*udpClient
	mutex    sync.Mutex
	drop     func(b []byte) bool
	received atomic.Int32
	dropped  atomic.Int32
}

func (c *lossyClient) setDrop(drop func(b []byte) bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.drop = drop
}

func (c *lossyClient) Receive(ctx context.Context) ([]byte, error) {
	// The CASE handshake's deadline does not outlive it.
	if _, ok := ctx.Deadline(); !ok {
		_ = c.conn.SetReadDeadline(time.Time{})
	}
	for {
		b, err := c.udpClient.Receive(ctx)
		if err != nil {
			return nil, err
		}
		c.received.Add(1)
		c.mutex.Lock()
		drop := c.drop != nil && c.drop(b)
		c.mutex.Unlock()
		if !drop {
			return b, nil
		}
		c.dropped.Add(1)
	}
}

// dropFirst drops the first packet match selects.
func dropFirst(match func(b []byte) bool) func(b []byte) bool {
	var done bool
	return func(b []byte) bool {
		if done || !match(b) {
			return false
		}
		done = true
		return true
	}
}

// lossySession commissions the device and opens a second CASE session to
// it over a lossyClient, with an On command which counts its runs.
func lossySession(t *testing.T, opts ...session.SecureSessionOption) (*lossyClient, session.SecureSession, *atomic.Int32) {
	t.Helper()
	d, adv, ca, _, _ := commissionedDevice(t)
	waitOperational(t, adv, 1)
	ep, err := d.AddEndpoint(1, OnOffLightDeviceType)
	if err != nil {
		t.Fatal(err)
	}
	var runs atomic.Int32
	ep.HandleCommand(0x0006, 0x01, func(*im.CommandRequest) im.CommandResult {
		runs.Add(1)
		ep.NotifyAttributeChanged(0x0006, 0x0000)
		return im.CommandStatus(im.StatusSuccess)
	})
	ep.HandleAttribute(0x0006, 0x0000, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		enc.PutBool(tag, 0 < runs.Load())
		return im.StatusSuccess
	})
	client := &lossyClient{udpClient: dialDevice(t, d), mutex: sync.Mutex{}, drop: nil}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	keys, err := caseprotocol.NewInitiator(client, ca.admin(t, testAdminNodeID), caseprotocol.WithPeerNodeID(testCommissioneeNode), caseprotocol.WithIPK(testIPK)).EstablishSession(ctx)
	if err != nil {
		t.Fatalf("CASE: %v", err)
	}
	return client, session.NewSecureSession(client, keys, opts...), &runs
}

// TestDeviceRetransmitsLostResponse drops the device's InvokeResponse: the
// device sends it again, as the controller did not acknowledge it.
func TestDeviceRetransmitsLostResponse(t *testing.T) {
	client, sess, runs := lossySession(t)
	client.setDrop(dropFirst(func(b []byte) bool { return standaloneAckSize < len(b) }))
	start := time.Now()
	resp, err := im.Invoke(sess, 1, 0x0006, 0x01, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !resp.IsSuccess() {
		t.Fatalf("Invoke status %+v", resp.Status)
	}
	if client.dropped.Load() != 1 {
		t.Fatalf("%d packets dropped, want the first response", client.dropped.Load())
	}
	if elapsed := time.Since(start); elapsed < session.DefaultActiveRetransmitInterval {
		t.Fatalf("the response came after %v, sooner than a retransmission", elapsed)
	}
	if n := runs.Load(); n != 1 {
		t.Fatalf("the command ran %d times, want once", n)
	}
	// Acknowledged, the response is not sent again.
	received := client.received.Load()
	time.Sleep(time.Second)
	if n := client.received.Load(); n != received {
		t.Fatalf("the device sent %d more packets after the ack", n-received)
	}
}

// TestDeviceIgnoresRetransmittedRequest drops the device's ack of an
// InvokeRequest, so the controller sends the request again: the device
// acknowledges it again, and runs the command once.
func TestDeviceIgnoresRetransmittedRequest(t *testing.T) {
	client, sess, runs := lossySession(t, session.WithRetransmission(50*time.Millisecond, session.DefaultMaxTransmissions))
	client.setDrop(dropFirst(func(b []byte) bool { return len(b) <= standaloneAckSize }))
	resp, err := im.Invoke(sess, 1, 0x0006, 0x01, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !resp.IsSuccess() {
		t.Fatalf("Invoke status %+v", resp.Status)
	}
	if client.dropped.Load() != 1 {
		t.Fatalf("%d packets dropped, want the first ack", client.dropped.Load())
	}
	// The retransmitted request arrives on its own schedule.
	time.Sleep(500 * time.Millisecond)
	if n := runs.Load(); n != 1 {
		t.Fatalf("the command ran %d times, want once", n)
	}
}

// sendIM sends an Interaction Model message on exchange, as its initiator
// when initiator.
func sendIM(t *testing.T, sess session.SecureSession, opcode message.Opcode, exchange message.ExchangeID, initiator bool, payload []byte) {
	t.Helper()
	flags := message.ExchangeFlag(message.ReliabilityFlag)
	if initiator {
		flags |= message.InitiatorFlag
	}
	hdr, err := message.NewProtocolHeader(
		message.WithHeaderExchangeFlags(flags),
		message.WithHeaderOpcode(opcode),
		message.WithHeaderExchangeID(exchange),
		message.WithHeaderProtocolID(message.InteractionModel),
	).Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.Transmit(append(hdr, payload...)); err != nil {
		t.Fatal(err)
	}
}

func receiveIMOpcode(t *testing.T, sess session.SecureSession, opcode message.Opcode) {
	t.Helper()
	raw, err := sess.Receive()
	if err != nil {
		t.Fatal(err)
	}
	hdr, err := message.NewProtocolHeaderFromBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	if hdr.Opcode() != opcode {
		t.Fatalf("received opcode 0x%02X, want 0x%02X", uint8(hdr.Opcode()), uint8(opcode))
	}
}

// TestDeviceEndsSubscriptionOnUndeliveredReport subscribes to OnOff, then
// drops every packet from the device: the device sends the report of a
// change MRP_MAX_TRANSMISSIONS times, then ends the subscription, so a
// later change is not reported.
func TestDeviceEndsSubscriptionOnUndeliveredReport(t *testing.T) {
	if testing.Short() {
		t.Skip("waits out the retransmissions; skipped with -short")
	}
	client, sess, _ := lossySession(t)

	// 8.5.1. SubscribeRequest: OnOff of endpoint 1, max interval 60 s.
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	enc.PutBool(tlv.NewContextTag(0), false)
	enc.PutUnsigned2(tlv.NewContextTag(1), 0)
	enc.PutUnsigned2(tlv.NewContextTag(2), 60)
	enc.BeginArray(tlv.NewContextTag(3))
	enc.BeginList(tlv.NewAnonymousTag())
	enc.PutUnsigned2(tlv.NewContextTag(2), 1)
	enc.PutUnsigned4(tlv.NewContextTag(3), 0x0006)
	enc.PutUnsigned4(tlv.NewContextTag(4), 0x0000)
	_ = enc.EndContainer()
	_ = enc.EndContainer()
	enc.PutBool(tlv.NewContextTag(7), false)
	enc.PutUnsigned1(tlv.NewContextTag(0xFF), 12)
	if err := enc.EndContainer(); err != nil {
		t.Fatal(err)
	}
	exchange := message.NewFirstExchangeID()
	sendIM(t, sess, message.SubscribeRequestMessage, exchange, true, enc.Bytes())
	receiveIMOpcode(t, sess, message.ReportDataMessage)
	status := tlv.NewEncoder()
	status.BeginStructure(tlv.NewAnonymousTag())
	status.PutUnsigned1(tlv.NewContextTag(0), 0)
	status.PutUnsigned1(tlv.NewContextTag(0xFF), 12)
	if err := status.EndContainer(); err != nil {
		t.Fatal(err)
	}
	sendIM(t, sess, message.StatusResponseMessage, exchange, true, status.Bytes())
	receiveIMOpcode(t, sess, message.SubscribeResponseMessage)

	// From now on nothing the device sends arrives.
	client.setDrop(func([]byte) bool { return true })
	before := client.received.Load()
	go func() {
		for {
			if _, err := sess.Receive(); err != nil {
				return
			}
		}
	}()
	sendIM(t, sess, message.InvokeRequestMessage, message.NewFirstExchangeID(), true, invokeOn(t))
	// The InvokeResponse and the change's report are each sent
	// DefaultMaxTransmissions times, besides the ack of the request.
	want := before + 1 + 2*session.DefaultMaxTransmissions
	waitForWithin(t, 10*time.Second, "the device's retransmissions", func() bool { return client.received.Load() == want })
	// The device gives up up to 1.7 s after the last transmission
	// (4.12.8.1: MRP_BACKOFF_BASE^3 backoff with jitter).
	time.Sleep(2500 * time.Millisecond)
	client.setDrop(nil)
	received := client.received.Load()
	if received != want {
		t.Fatalf("the device sent %d packets, want %d", received-before, want-before)
	}
	sendIM(t, sess, message.InvokeRequestMessage, message.NewFirstExchangeID(), true, invokeOn(t))
	time.Sleep(time.Second)
	// The ack and response of the On, and no report.
	if n := client.received.Load() - received; n != 2 {
		t.Fatalf("the device sent %d packets after a change, want 2: no report of the ended subscription", n)
	}
}

func invokeOn(t *testing.T) []byte {
	t.Helper()
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	enc.PutBool(tlv.NewContextTag(0), false)
	enc.PutBool(tlv.NewContextTag(1), false)
	enc.BeginArray(tlv.NewContextTag(2))
	enc.BeginStructure(tlv.NewAnonymousTag())
	enc.BeginList(tlv.NewContextTag(0))
	enc.PutUnsigned2(tlv.NewContextTag(0), 1)
	enc.PutUnsigned4(tlv.NewContextTag(1), 0x0006)
	enc.PutUnsigned4(tlv.NewContextTag(2), 0x01)
	_ = enc.EndContainer()
	enc.BeginStructure(tlv.NewContextTag(1))
	_ = enc.EndContainer()
	_ = enc.EndContainer()
	_ = enc.EndContainer()
	enc.PutUnsigned1(tlv.NewContextTag(0xFF), 12)
	if err := enc.EndContainer(); err != nil {
		t.Fatal(err)
	}
	return enc.Bytes()
}

func waitForWithin(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestDeviceSessionsTakePeerMRPParameters checks that the device's PASE and
// CASE sessions retransmit at the intervals the commissioner announced,
// here the defaults its PBKDFParamRequest and Sigma1 carry. The PASE
// session is checked during commissioning, before it closes.
func TestDeviceSessionsTakePeerMRPParameters(t *testing.T) {
	d, _, pase, client := startCommissioningWithAdvertiser(t)
	checkPeerMRP := func(isCASE bool) {
		t.Helper()
		d.mu.Lock()
		defer d.mu.Unlock()
		for _, sess := range d.sessions {
			if sess.isCASE != isCASE {
				continue
			}
			got, ok := session.PeerMRPParameters(sess.secure)
			if !ok || got != session.DefaultMRPParameters() {
				t.Fatalf("the session (CASE %v) has peer parameters %+v, %v; want the commissioner's %+v", isCASE, got, ok, session.DefaultMRPParameters())
			}
			return
		}
		t.Fatalf("no session (CASE %v)", isCASE)
	}
	checkPeerMRP(false)
	ca := newTestCA(t, testFabricID)
	addNOCOverPASE(t, pase, ca, testCommissioneeNode)
	caseSession(t, client, ca.admin(t, testAdminNodeID), testCommissioneeNode)
	checkPeerMRP(true)
}
