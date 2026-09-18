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
	"context"
	"encoding/binary"
	"fmt"
	"sync/atomic"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter/crypto"
	"github.com/cybergarage/go-matter/matter/encoding/message"
)

// secureSession is the concrete implementation of SecureSession.
type secureSession struct {
	t          Transport
	keys       SessionKeys
	msgCounter uint32 // atomic outbound message counter
}

// NewSecureSession creates a SecureSession from an established PASE session.
// The session uses the I2RKey for encryption of outbound messages and R2IKey
// for decryption of inbound messages.
// 4.7. Encryption.
func NewSecureSession(t Transport, keys SessionKeys) SecureSession {
	return &secureSession{
		t:          t,
		keys:       keys,
		msgCounter: uint32(message.NewMessageCounter()),
	}
}

// Transport returns the underlying raw transport.
func (s *secureSession) Transport() Transport {
	return s.t
}

// SessionKeys returns the session keys for this session.
func (s *secureSession) SessionKeys() SessionKeys {
	return s.keys
}

// Transmit encrypts payload using AES-128-CCM with the I2RKey and transmits it.
//
// Outgoing message format (spec section 4.7):
//
//	[unencrypted message header] [AES-CCM ciphertext of (payload)] [16-byte MIC]
//
// The SessionID field in the message header is set to the responder's session ID
// so the remote peer can look up the session context. The source node ID present
// in the header is the initiator's node ID established during the PASE handshake.
// 4.7. Encryption.
func (s *secureSession) Transmit(payload []byte) error {
	// Atomically increment the outbound message counter.
	counter := atomic.AddUint32(&s.msgCounter, 1)

	// Build the unencrypted message header. SecurityFlags = 0x00: unicast
	// session, no privacy, no extensions. The Source/Destination Node ID
	// fields are omitted: within an established secure unicast session, the
	// SessionID alone identifies the peer, and connectedhomeip's own
	// PrepareMessage does not set them for this message type (only for
	// group messages) — see session.SessionKeys.LocalNodeID's doc comment
	// for how the (unrelated) CCM nonce's node ID is still determined.
	secFlags := message.SecurityFlag(0x00)
	hdr := message.NewHeader(
		message.WithHeaderSessionID(s.keys.ResponderSessionID()),
		message.WithHeaderSecurityFlags(secFlags),
		message.WithHeaderMessageCounter(message.MessageCounter(counter)),
	)

	hdrBytes, err := hdr.Bytes()
	if err != nil {
		return fmt.Errorf("session: failed to serialize message header: %w", err)
	}

	// Build the CCM nonce (spec section 4.7.2).
	// nonce = SecurityFlags(1) || MessageCounter(4, LE) || SourceNodeID(8, LE)
	nodeID := uint64(s.keys.LocalNodeID())
	nonce := crypto.CryptoCCMNonce(byte(secFlags), counter, nodeID)

	// Encrypt payload using I2RKey (initiator-to-responder).
	// AAD = the serialized message header bytes.
	ciphertextWithTag, err := crypto.CryptoCCMEncrypt(s.keys.I2RKey(), nonce, payload, hdrBytes)
	if err != nil {
		return fmt.Errorf("session: AES-CCM encryption failed: %w", err)
	}

	// Compose the on-wire packet: header || ciphertext || tag.
	wire := make([]byte, 0, len(hdrBytes)+len(ciphertextWithTag))
	wire = append(wire, hdrBytes...)
	wire = append(wire, ciphertextWithTag...)

	log.HexDebug(wire)
	return s.t.Transmit(context.Background(), wire)
}

// Receive reads one message from the transport, decrypts it using the R2IKey, and
// returns the decrypted payload (protocol header + application payload bytes).
// 4.7. Encryption.
func (s *secureSession) Receive() ([]byte, error) {
	ctx := context.Background()
	raw, err := s.t.Receive(ctx)
	if err != nil {
		return nil, err
	}
	if len(raw) < 8 {
		return nil, fmt.Errorf("session: received packet too short (%d bytes)", len(raw))
	}

	// Parse the message header to determine its byte length.
	hdr, err := message.NewHeaderFromBytes(raw)
	if err != nil {
		return nil, fmt.Errorf("session: failed to parse message header: %w", err)
	}

	// Compute the byte length of the header to split header from ciphertext.
	hdrBytes, err := hdr.Bytes()
	if err != nil {
		return nil, fmt.Errorf("session: failed to serialize parsed header: %w", err)
	}
	if len(raw) < len(hdrBytes) {
		return nil, fmt.Errorf("session: packet shorter than header (%d < %d)", len(raw), len(hdrBytes))
	}
	ciphertextWithTag := raw[len(hdrBytes):]

	// Build nonce (spec section 4.7.2). The node ID component is the peer's
	// node ID as known from session establishment (s.keys.PeerNodeID()) —
	// NOT read from this packet's header, which typically omits the Source
	// Node ID field entirely for secure unicast session messages (see the
	// matching comment in Transmit). connectedhomeip's SessionManager
	// resolves this the same way: PeerNodeId() for CASE, the fixed
	// "undefined" node ID (0) for PASE.
	msgCounter := uint32(hdr.MessageCounter())
	nonce := make([]byte, 13)
	nonce[0] = byte(hdr.SecurityFlags())
	binary.LittleEndian.PutUint32(nonce[1:5], msgCounter)
	binary.LittleEndian.PutUint64(nonce[5:13], uint64(s.keys.PeerNodeID()))

	// Decrypt using R2IKey (responder-to-initiator).
	plaintext, err := crypto.CryptoCCMDecrypt(s.keys.R2IKey(), nonce, ciphertextWithTag, hdrBytes)
	if err != nil {
		return nil, fmt.Errorf("session: AES-CCM decryption failed: %w", err)
	}

	return plaintext, nil
}
