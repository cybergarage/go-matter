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
	"testing"

	"github.com/cybergarage/go-matter/matter/encoding/message"
)

// pipe is one end of an in-memory, message-preserving pipe.
type pipe struct {
	in  <-chan []byte
	out chan<- []byte
}

func newPipePair() (*pipe, *pipe) {
	a2b := make(chan []byte, 8)
	b2a := make(chan []byte, 8)
	return &pipe{in: b2a, out: a2b}, &pipe{in: a2b, out: b2a}
}

func (p *pipe) Transmit(_ context.Context, b []byte) error {
	p.out <- bytes.Clone(b)
	return nil
}

func (p *pipe) Receive(ctx context.Context) ([]byte, error) {
	select {
	case b := <-p.in:
		return b, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// protocolPayload builds a protocol header, with the given exchange flags,
// followed by body.
func protocolPayload(t *testing.T, flags message.ExchangeFlag, body string) []byte {
	t.Helper()
	hdr, err := message.NewProtocolHeader(
		message.WithHeaderExchangeFlags(flags),
		message.WithHeaderOpcode(message.Opcode(0x08)),
		message.WithHeaderExchangeID(7),
		message.WithHeaderProtocolID(message.InteractionModel),
	).Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return append(hdr, body...)
}

func TestSecureSessionRoles(t *testing.T) {
	keys := &stubSessionKeys{i2rKey: bytes.Repeat([]byte{1}, 16), r2iKey: bytes.Repeat([]byte{2}, 16)}
	initT, respT := newPipePair()
	initiator := NewSecureSession(initT, keys)
	responder := NewSecureSession(respT, keys, WithRole(RoleResponder))

	// Initiator to responder: a request which asks for an ack.
	request := protocolPayload(t, message.InitiatorFlag|message.ReliabilityFlag, "request")
	if err := initiator.Transmit(request); err != nil {
		t.Fatal(err)
	}
	got, err := responder.Receive()
	if err != nil {
		t.Fatalf("responder Receive() error = %v", err)
	}
	if !bytes.Equal(got, request) {
		t.Fatalf("responder received %q, want %q", got, request)
	}

	// The responder acknowledged it, without the initiator flag, since the
	// initiator opened the exchange.
	ackRaw := <-initT.in
	hdr, err := message.NewHeaderFromBytes(ackRaw)
	if err != nil {
		t.Fatal(err)
	}
	if hdr.SessionID() != keys.InitiatorSessionID() {
		t.Fatalf("the responder addressed session %d, want the initiator's %d", hdr.SessionID(), keys.InitiatorSessionID())
	}
	initT2, _ := newPipePair()
	ackReader := NewSecureSession(&replayTransport{packets: [][]byte{ackRaw}, sink: initT2}, keys)
	plain, _, err := ackReader.(*secureSession).receiveOne()
	if err != nil {
		t.Fatalf("decrypt the responder's ack: %v", err)
	}
	ack, err := message.NewProtocolHeaderFromBytes(plain)
	if err != nil {
		t.Fatal(err)
	}
	if !ack.Opcode().IsMRPStandaloneAck() || ack.IsInitiator() {
		t.Fatalf("responder ack: opcode %#x, initiator flag %v; want a standalone ack without it", uint8(ack.Opcode()), ack.IsInitiator())
	}

	// Responder to initiator: the response.
	response := protocolPayload(t, 0, "response")
	if err := responder.Transmit(response); err != nil {
		t.Fatal(err)
	}
	got, err = initiator.Receive()
	if err != nil {
		t.Fatalf("initiator Receive() error = %v", err)
	}
	if !bytes.Equal(got, response) {
		t.Fatalf("initiator received %q, want %q", got, response)
	}
}

func TestSecureSessionRejectsTheOtherRolesTraffic(t *testing.T) {
	keys := &stubSessionKeys{i2rKey: bytes.Repeat([]byte{1}, 16), r2iKey: bytes.Repeat([]byte{2}, 16)}
	aT, bT := newPipePair()
	// Two initiators: each addresses the responder's session ID, which
	// neither of them accepts.
	a := NewSecureSession(aT, keys)
	b := NewSecureSession(&replayTransport{packets: nil, sink: bT}, keys)
	if err := a.Transmit(protocolPayload(t, message.InitiatorFlag, "x")); err != nil {
		t.Fatal(err)
	}
	raw := <-bT.in
	b.(*secureSession).t = &replayTransport{packets: [][]byte{raw}, sink: bT}
	if _, _, err := b.(*secureSession).receiveOne(); err == nil {
		t.Fatal("an initiator accepted a message addressed to the responder's session ID")
	}
}

// replayTransport returns queued packets and sends to sink.
type replayTransport struct {
	packets [][]byte
	sink    *pipe
}

func (r *replayTransport) Transmit(ctx context.Context, b []byte) error {
	return r.sink.Transmit(ctx, b)
}

func (r *replayTransport) Receive(context.Context) ([]byte, error) {
	p := r.packets[0]
	r.packets = r.packets[1:]
	return p, nil
}
