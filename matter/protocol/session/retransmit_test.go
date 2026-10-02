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

package session

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/cybergarage/go-matter/matter/encoding/message"
)

// countingTransport delivers what it transmits to peer's in channel, and
// counts the transmissions.
type countingTransport struct {
	mutex sync.Mutex
	sent  int
	in    chan []byte
	out   chan []byte
}

func (t *countingTransport) Transmit(_ context.Context, b []byte) error {
	t.mutex.Lock()
	t.sent++
	t.mutex.Unlock()
	select {
	case t.out <- append([]byte(nil), b...):
	default:
	}
	return nil
}

func (t *countingTransport) Receive(ctx context.Context) ([]byte, error) {
	select {
	case b := <-t.in:
		return b, nil
	case <-time.After(2 * time.Second):
		return nil, errors.New("no packet")
	}
}

func (t *countingTransport) count() int {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.sent
}

func reliableMessage(t *testing.T, exchange message.ExchangeID, initiator bool) []byte {
	t.Helper()
	flags := message.ExchangeFlag(message.ReliabilityFlag)
	if initiator {
		flags |= message.InitiatorFlag
	}
	hdr, err := message.NewProtocolHeader(
		message.WithHeaderExchangeFlags(flags),
		message.WithHeaderOpcode(message.InvokeRequestMessage),
		message.WithHeaderExchangeID(exchange),
		message.WithHeaderProtocolID(message.InteractionModel),
	).Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return append(hdr, 0x15, 0x18)
}

func sessionPair(interval time.Duration, maxTransmissions int) (*countingTransport, SecureSession, *countingTransport, SecureSession) {
	a2b := make(chan []byte, 16)
	b2a := make(chan []byte, 16)
	keys := &stubSessionKeys{i2rKey: bytes.Repeat([]byte{1}, 16), r2iKey: bytes.Repeat([]byte{2}, 16)}
	ct := &countingTransport{mutex: sync.Mutex{}, sent: 0, in: b2a, out: a2b}
	dt := &countingTransport{mutex: sync.Mutex{}, sent: 0, in: a2b, out: b2a}
	client := NewSecureSession(ct, keys, WithRetransmission(interval, maxTransmissions))
	device := NewSecureSession(dt, keys, WithRole(RoleResponder))
	return ct, client, dt, device
}

func TestRetransmitUntilAcknowledged(t *testing.T) {
	ct, client, _, _ := sessionPair(10*time.Millisecond, 3)
	if err := client.Transmit(reliableMessage(t, 1, true)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	if n := ct.count(); n != 3 {
		t.Fatalf("an unacknowledged message was sent %d times, want 3", n)
	}
}

func TestRetransmitStopsOnAck(t *testing.T) {
	ct, client, _, device := sessionPair(50*time.Millisecond, 5)
	if err := client.Transmit(reliableMessage(t, 1, true)); err != nil {
		t.Fatal(err)
	}
	// The device receives the request, which acknowledges it, and answers.
	if _, err := device.Receive(); err != nil {
		t.Fatal(err)
	}
	if err := device.Transmit(reliableMessage(t, 1, false)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Receive(); err != nil {
		t.Fatal(err)
	}
	sent := ct.count() // the request and the client's ack of the answer
	time.Sleep(400 * time.Millisecond)
	if n := ct.count(); n != sent {
		t.Fatalf("the client went on sending after the ack: %d, then %d", sent, n)
	}
}

func TestCounterWindow(t *testing.T) {
	var w counterWindow
	steps := []struct {
		counter uint32
		isNew   bool
	}{
		{100, true}, {100, false}, {101, true}, {99, true}, {99, false},
		{140, true}, {101, false}, {108, true}, {108, false}, {107, false},
		{141, true}, {109, true}, {109, false}, {200, true}, {168, true}, {167, false},
	}
	for i, step := range steps {
		if got := w.accept(message.MessageCounter(step.counter)); got != step.isNew {
			t.Fatalf("step %d: accept(%d) = %v, want %v", i, step.counter, got, step.isNew)
		}
	}
}

// TestDuplicateIsAckedNotDelivered checks that a message received again,
// as when the peer missed its ack, is acknowledged again but not returned
// twice.
func TestDuplicateIsAckedNotDelivered(t *testing.T) {
	ct, client, dt, device := sessionPair(time.Second, 1)
	if err := client.Transmit(reliableMessage(t, 1, true)); err != nil {
		t.Fatal(err)
	}
	wire := <-ct.out
	ct.out <- wire
	ct.out <- wire
	if _, err := device.Receive(); err != nil {
		t.Fatal(err)
	}
	if err := client.Transmit(reliableMessage(t, 2, true)); err != nil {
		t.Fatal(err)
	}
	got, err := device.Receive()
	if err != nil {
		t.Fatal(err)
	}
	hdr, err := message.NewProtocolHeaderFromBytes(got)
	if err != nil {
		t.Fatal(err)
	}
	if hdr.ExchangeID() != 2 {
		t.Fatalf("the device received exchange %d, want 2 after dropping the duplicate", hdr.ExchangeID())
	}
	if n := dt.count(); n != 3 {
		t.Fatalf("the device sent %d acks, want 3: the message, its duplicate and the next", n)
	}
}

func TestUndeliveredHandler(t *testing.T) {
	a2b := make(chan []byte, 16)
	keys := &stubSessionKeys{i2rKey: bytes.Repeat([]byte{1}, 16), r2iKey: bytes.Repeat([]byte{2}, 16)}
	ct := &countingTransport{mutex: sync.Mutex{}, sent: 0, in: make(chan []byte), out: a2b}
	undelivered := make(chan message.ProtocolHeader, 1)
	client := NewSecureSession(ct, keys,
		WithRetransmission(10*time.Millisecond, 2),
		WithUndeliveredHandler(func(hdr message.ProtocolHeader) { undelivered <- hdr }),
	)
	if err := client.Transmit(reliableMessage(t, 7, true)); err != nil {
		t.Fatal(err)
	}
	select {
	case hdr := <-undelivered:
		if hdr.ExchangeID() != 7 || hdr.Opcode() != message.InvokeRequestMessage {
			t.Fatalf("undelivered exchange %d opcode 0x%02X, want exchange 7's InvokeRequest", hdr.ExchangeID(), uint8(hdr.Opcode()))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the undelivered message was not reported")
	}
	if n := ct.count(); n != 2 {
		t.Fatalf("the message was sent %d times, want 2", n)
	}
}

func TestStopRetransmissions(t *testing.T) {
	ct, client, _, _ := sessionPair(10*time.Millisecond, 5)
	if err := client.Transmit(reliableMessage(t, 1, true)); err != nil {
		t.Fatal(err)
	}
	StopRetransmissions(client)
	if err := client.Transmit(reliableMessage(t, 2, true)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if n := ct.count(); n != 2 {
		t.Fatalf("%d messages were sent, want the 2 transmissions only", n)
	}
}
