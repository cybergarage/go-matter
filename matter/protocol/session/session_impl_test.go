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

package session

import (
	"bytes"
	"context"
	"testing"

	"github.com/cybergarage/go-matter/matter/crypto"
	"github.com/cybergarage/go-matter/matter/encoding/message"
)

type stubSessionKeys struct {
	i2rKey, r2iKey []byte
}

func (k *stubSessionKeys) I2RKey() []byte                { return k.i2rKey }
func (k *stubSessionKeys) R2IKey() []byte                { return k.r2iKey }
func (k *stubSessionKeys) InitiatorSessionID() SessionID { return 1 }
func (k *stubSessionKeys) ResponderSessionID() SessionID { return 2 }
func (k *stubSessionKeys) LocalNodeID() NodeID           { return 0 }
func (k *stubSessionKeys) PeerNodeID() NodeID            { return 0 }
func (k *stubSessionKeys) AttestationChallenge() []byte  { return nil }

// queueTransport replays a fixed queue of packets on Receive and records
// everything sent via Transmit.
type queueTransport struct {
	packets   [][]byte
	transmits [][]byte
}

func (t *queueTransport) Transmit(ctx context.Context, b []byte) error {
	t.transmits = append(t.transmits, append([]byte{}, b...))
	return nil
}

func (t *queueTransport) Receive(ctx context.Context) ([]byte, error) {
	p := t.packets[0]
	t.packets = t.packets[1:]
	return p, nil
}

// encryptDeviceMessage builds a secure-unicast wire packet as a responder
// device would send it: an unencrypted message.Header followed by the
// AES-CCM ciphertext of plaintext under key, keyed to the given message
// counter (the nonce's other component, the node ID, is fixed at 0 to match
// stubSessionKeys.PeerNodeID, mirroring PASE's convention).
func encryptDeviceMessage(t *testing.T, key []byte, counter uint32, plaintext []byte) []byte {
	t.Helper()
	secFlags := message.SecurityFlag(0x00)
	hdr := message.NewHeader(
		message.WithHeaderSessionID(1),
		message.WithHeaderSecurityFlags(secFlags),
		message.WithHeaderMessageCounter(message.MessageCounter(counter)),
	)
	hdrBytes, err := hdr.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	nonce := crypto.CryptoCCMNonce(byte(secFlags), counter, 0)
	ciphertext, err := crypto.CryptoCCMEncrypt(key, nonce, plaintext, hdrBytes)
	if err != nil {
		t.Fatal(err)
	}
	return append(hdrBytes, ciphertext...)
}

// TestSecureSessionReceiveSkipsStandaloneMRPAck guards against a regression
// where a real device's standalone MRP acknowledgement (opcode 0x10,
// SecureChannel protocol, no application payload) — sent to satisfy the
// sender's retransmission timer while it prepares a slower response, e.g.
// AttestationRequest's DAC signing operation — was returned by Receive as if
// it were the actual application response. The caller (im.Invoke /
// im.ReadBoolAttribute) would then fail to find any expected fields in an
// essentially empty message. PASE's Initiator.receiveSkipAck and CASE's
// client.go already apply this same skip-and-retry pattern to the
// unencrypted handshake phase; secureSession.Receive needed the same
// treatment for the encrypted post-handshake session.
func TestSecureSessionReceiveSkipsStandaloneMRPAck(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 16)
	keys := &stubSessionKeys{i2rKey: key, r2iKey: key}

	ackHdr := message.NewProtocolHeader(
		message.WithHeaderOpcode(message.MRPStandaloneAck),
		message.WithHeaderExchangeID(1),
		message.WithHeaderProtocolID(message.SecureChannel),
	)
	ackBytes, err := ackHdr.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	realPayload := []byte("real-invoke-response-payload")

	transport := &queueTransport{packets: [][]byte{
		encryptDeviceMessage(t, key, 1, ackBytes),
		encryptDeviceMessage(t, key, 2, realPayload),
	}}

	sess := NewSecureSession(transport, keys)
	got, err := sess.Receive()
	if err != nil {
		t.Fatalf("Receive() error = %v", err)
	}
	if !bytes.Equal(got, realPayload) {
		t.Errorf("Receive() = %q, want %q (the standalone MRP ACK should have been skipped)", got, realPayload)
	}
}

// TestSecureSessionReceiveSkipsForeignSessionPacket guards against a
// regression where a stray packet not addressed to this session — observed
// against a real device as a 34-byte packet with SessionID 0 and an unrelated
// destination-node-ID field, most likely a delayed/duplicate message from an
// earlier unsecured exchange — was handed straight to AES-CCM decryption,
// which can only ever fail authentication since it was never encrypted with
// this session's keys. That surfaced as a fatal "AES-CCM decryption failed"
// error instead of being ignored so the real, matching response could still
// arrive. A SessionID that doesn't match InitiatorSessionID (the ID this
// session told its peer to use) is now rejected before decryption is even
// attempted, and Receive retries instead of failing.
func TestSecureSessionReceiveSkipsForeignSessionPacket(t *testing.T) {
	key := bytes.Repeat([]byte{0x22}, 16)
	keys := &stubSessionKeys{i2rKey: key, r2iKey: key}

	// A packet whose header claims SessionID 0 (this session expects 1) —
	// its ciphertext content is irrelevant since it must be rejected before
	// any decryption is attempted.
	foreignHdr := message.NewHeader(
		message.WithHeaderSessionID(0),
		message.WithHeaderSecurityFlags(0),
		message.WithHeaderMessageCounter(99),
	)
	foreignHdrBytes, err := foreignHdr.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	foreignPacket := append(append([]byte{}, foreignHdrBytes...), 0xDE, 0xAD, 0xBE, 0xEF)

	realPayload := []byte("real-invoke-response-payload")

	transport := &queueTransport{packets: [][]byte{
		foreignPacket,
		encryptDeviceMessage(t, key, 2, realPayload),
	}}

	sess := NewSecureSession(transport, keys)
	got, err := sess.Receive()
	if err != nil {
		t.Fatalf("Receive() error = %v", err)
	}
	if !bytes.Equal(got, realPayload) {
		t.Errorf("Receive() = %q, want %q (the foreign-session packet should have been skipped)", got, realPayload)
	}
}

// decryptWireMessage decrypts a wire packet transmitted by a secureSession
// (I2RKey, LocalNodeID 0, per stubSessionKeys) and returns the decrypted
// protocol-header-only plaintext.
func decryptWireMessage(t *testing.T, key []byte, wire []byte) message.ProtocolHeader {
	t.Helper()
	hdr, err := message.NewHeaderFromBytes(wire)
	if err != nil {
		t.Fatal(err)
	}
	hdrBytes, err := hdr.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	nonce := crypto.CryptoCCMNonce(byte(hdr.SecurityFlags()), uint32(hdr.MessageCounter()), 0)
	plaintext, err := crypto.CryptoCCMDecrypt(key, nonce, wire[len(hdrBytes):], hdrBytes)
	if err != nil {
		t.Fatal(err)
	}
	protHdr, err := message.NewProtocolHeaderFromBytes(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	return protHdr
}

// TestSecureSessionReceiveSendsMRPAckForReliableMessage guards against a
// regression where Receive never acknowledged any reliable message it got
// (im.Invoke / im.ReadBoolAttribute each open a brand-new, unrelated
// exchange per call, so nothing else in the request/response flow ever
// referenced a prior response's message counter). Against a real device,
// this meant every response went permanently unacknowledged; the device
// retransmitted an early response (per its own MRP retry schedule) much
// later in the session, and that stray retransmission — sharing this
// session's SessionID, so the earlier foreign-session filter didn't catch it
// — arrived interleaved with an unrelated later exchange and was
// misinterpreted as its response. Receive must send a standalone MRP ack
// (opcode 0x10) referencing the received message's ExchangeID, ProtocolID
// and MessageCounter immediately after receiving any reliable message, so
// the device has no reason to retransmit it.
func TestSecureSessionReceiveSendsMRPAckForReliableMessage(t *testing.T) {
	key := bytes.Repeat([]byte{0x33}, 16)
	keys := &stubSessionKeys{i2rKey: key, r2iKey: key}

	respHdr := message.NewProtocolHeader(
		message.WithHeaderExchangeFlags(message.AckFlag|message.ReliabilityFlag),
		message.WithHeaderOpcode(message.InvokeResponseMessage),
		message.WithHeaderExchangeID(0xBEEF),
		message.WithHeaderProtocolID(message.InteractionModel),
	)
	respBytes, err := respHdr.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	const receivedCounter = 42
	transport := &queueTransport{packets: [][]byte{
		encryptDeviceMessage(t, key, receivedCounter, respBytes),
	}}

	sess := NewSecureSession(transport, keys)
	if _, err := sess.Receive(); err != nil {
		t.Fatalf("Receive() error = %v", err)
	}

	if len(transport.transmits) != 1 {
		t.Fatalf("transport.transmits has %d entries, want 1 (the MRP ack)", len(transport.transmits))
	}
	ackProtHdr := decryptWireMessage(t, key, transport.transmits[0])

	if !ackProtHdr.Opcode().IsMRPStandaloneAck() {
		t.Errorf("ack Opcode() = %v, want MRPStandaloneAck", ackProtHdr.Opcode())
	}
	if got := ackProtHdr.ExchangeID(); got != 0xBEEF {
		t.Errorf("ack ExchangeID() = %#x, want 0xBEEF", got)
	}
	if got := ackProtHdr.ProtocolID(); got != message.InteractionModel {
		t.Errorf("ack ProtocolID() = %v, want InteractionModel", got)
	}
	ackedCounter, ok := ackProtHdr.AckMessageCounter()
	if !ok {
		t.Fatal("ack AckMessageCounter() not present")
	}
	if ackedCounter != receivedCounter {
		t.Errorf("ack AckMessageCounter() = %d, want %d", ackedCounter, receivedCounter)
	}
}
