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

// queueTransport replays a fixed queue of packets on Receive and discards
// anything sent via Transmit.
type queueTransport struct {
	packets [][]byte
}

func (t *queueTransport) Transmit(ctx context.Context, b []byte) error { return nil }

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
