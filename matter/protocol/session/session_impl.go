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
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter/crypto"
	"github.com/cybergarage/go-matter/matter/encoding/message"
)

// errForeignSession is returned by receiveOne when a packet's SessionID
// doesn't match this session's expected InitiatorSessionID, meaning it
// wasn't addressed to this session at all (e.g. a stray or delayed packet
// from an earlier unsecured exchange, such as a late PASE-phase message
// arriving after the secure session is already established). Receive treats
// it the same way as a standalone MRP ack: skip it and wait for the next
// packet, rather than attempting to AES-CCM-decrypt data that was never
// encrypted for this session's keys in the first place.
var errForeignSession = errors.New("session: packet does not belong to this session")

// Role is the side of session establishment this node took, which decides
// which of the session's keys and session IDs it sends and receives with.
type Role int

const (
	// RoleInitiator is the side which started session establishment, such
	// as a commissioner: it encrypts with I2RKey, decrypts with R2IKey, and
	// addresses the peer by ResponderSessionID.
	RoleInitiator Role = iota
	// RoleResponder is the side which answered it, such as a device being
	// commissioned: it encrypts with R2IKey, decrypts with I2RKey, and
	// addresses the peer by InitiatorSessionID.
	RoleResponder
)

// SecureSessionOption configures a SecureSession.
type SecureSessionOption func(*secureSession)

// WithRole sets the side this node took in session establishment. The
// default is RoleInitiator.
func WithRole(role Role) SecureSessionOption {
	return func(s *secureSession) {
		s.role = role
	}
}

// secureSession is the concrete implementation of SecureSession.
type secureSession struct {
	t          Transport
	keys       SessionKeys
	role       Role
	msgCounter uint32 // atomic outbound message counter
}

// NewSecureSession creates a SecureSession from established session keys.
// By default the session is the initiator's: it encrypts outbound messages
// with the I2RKey and decrypts inbound ones with the R2IKey. WithRole
// (RoleResponder) makes it the responder's, with the keys and session IDs
// the other way round.
// 4.7. Encryption.
func NewSecureSession(t Transport, keys SessionKeys, opts ...SecureSessionOption) SecureSession {
	s := &secureSession{
		t:          t,
		keys:       keys,
		role:       RoleInitiator,
		msgCounter: uint32(message.NewMessageCounter()),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// txKey and rxKey are the keys this side encrypts and decrypts with.
func (s *secureSession) txKey() []byte {
	if s.role == RoleResponder {
		return s.keys.R2IKey()
	}
	return s.keys.I2RKey()
}

func (s *secureSession) rxKey() []byte {
	if s.role == RoleResponder {
		return s.keys.I2RKey()
	}
	return s.keys.R2IKey()
}

// peerSessionID is the session ID the peer chose, which this side puts in
// the header of every message it sends; localSessionID is the one this side
// chose, which every message addressed to it carries (4.13.2.4).
func (s *secureSession) peerSessionID() SessionID {
	if s.role == RoleResponder {
		return s.keys.InitiatorSessionID()
	}
	return s.keys.ResponderSessionID()
}

func (s *secureSession) localSessionID() SessionID {
	if s.role == RoleResponder {
		return s.keys.ResponderSessionID()
	}
	return s.keys.InitiatorSessionID()
}

// Transport returns the underlying raw transport.
func (s *secureSession) Transport() Transport {
	return s.t
}

// SessionKeys returns the session keys for this session.
func (s *secureSession) SessionKeys() SessionKeys {
	return s.keys
}

// Transmit encrypts payload using AES-128-CCM with this side's outbound key
// and transmits it.
//
// Outgoing message format (spec section 4.7):
//
//	[unencrypted message header] [AES-CCM ciphertext of (payload)] [16-byte MIC]
//
// The SessionID field in the message header is set to the session ID the
// peer chose, so the remote peer can look up the session context. The CCM
// nonce uses this side's node ID (SessionKeys.LocalNodeID).
// 4.7. Encryption.
func (s *secureSession) Transmit(payload []byte) error {
	return s.transmitPayload(payload)
}

// transmitPayload does the actual encryption and send for Transmit and for
// sendAck, which needs to transmit a standalone MRP acknowledgement outside
// of the normal request/response flow.
func (s *secureSession) transmitPayload(payload []byte) error {
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
		message.WithHeaderSessionID(s.peerSessionID()),
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

	// Encrypt payload with this side's outbound key: I2RKey for the
	// initiator, R2IKey for the responder.
	// AAD = the serialized message header bytes.
	ciphertextWithTag, err := crypto.CryptoCCMEncrypt(s.txKey(), nonce, payload, hdrBytes)
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

// sendAck transmits a standalone MRP acknowledgement (opcode 0x10,
// SecureChannel protocol, no application payload) referencing a received
// reliable message's exchange and message counter. Without this, a real
// device retransmits every reliable message it never sees acknowledged,
// according to its own retry schedule — and since each IM call
// (im.Invoke / im.ReadBoolAttribute) opens a brand-new exchange with no
// relation to the previous one, nothing else in this client's request/
// response flow ever acknowledges a prior response. A late retransmission
// then arrives interleaved with a later, unrelated exchange and gets
// mistaken for its response.
//
// The InitiatorFlag reflects which peer initiated the *exchange*, not who
// happens to be sending this particular message, so every message a side
// sends within that exchange — including a standalone ack — carries it
// exactly when the acknowledged message did not: a commissioner acking a
// device's response to its own request sets it, and a device acking a
// commissioner's request leaves it clear. connectedhomeip's own ReliableMessageContext::
// SendStandaloneAckMessage sends acks through the same generic
// ExchangeContext::SendMessage path used for every other message on the
// exchange, which sets this flag from the exchange's stored role
// automatically; omitting it here left the device unable to match our ack
// to the exchange it was acknowledging, so it kept retransmitting anyway.
// 4.12.7.1. MRP Standalone Acknowledgement.
//
// The standalone ack always carries the Secure Channel protocol ID, never
// the acknowledged message's own protocol ID: a peer's MRP layer matches a
// standalone ack to the exchange it acknowledges by ExchangeID and role
// alone, and expects every standalone ack on the Secure Channel protocol
// regardless of which protocol the exchange itself is running. Carrying the
// acknowledged message's protocol ID instead (e.g. InteractionModel) left
// chip-tool unable to recognize the ack, so it treated it as an unexpected
// message on the exchange and kept its retransmission timer running.
func (s *secureSession) sendAck(exchangeID message.ExchangeID, ackedCounter message.MessageCounter, ackedFromInitiator bool) error {
	flags := message.ExchangeFlag(0)
	if !ackedFromInitiator {
		flags = message.InitiatorFlag
	}
	ackHdr := message.NewProtocolHeader(
		message.WithHeaderExchangeFlags(flags),
		message.WithHeaderExchangeID(exchangeID),
		message.WithHeaderProtocolID(message.SecureChannel),
		message.WithHeaderOpcode(message.MRPStandaloneAck),
		message.WithHeaderAckCounter(ackedCounter),
	)
	payload, err := ackHdr.Bytes()
	if err != nil {
		return fmt.Errorf("session: failed to build MRP ack: %w", err)
	}
	return s.transmitPayload(payload)
}

// Receive reads one message from the transport, decrypts it with this side's
// inbound key, and
// returns the decrypted payload (protocol header + application payload bytes).
// Standalone MRP acknowledgement messages (opcode 0x10, SecureChannel protocol,
// no application payload) are silently discarded and the next message is
// awaited instead: a responder that needs time to process a request (e.g.
// AttestationRequest, which involves a DAC signing operation) may send one to
// satisfy the sender's retransmission timer before the real response is
// ready, exactly as PASE's Initiator.receiveSkipAck and CASE's client.go
// already do for the unencrypted handshake phase — this is the same pattern
// applied to the encrypted post-handshake session.
// 4.7. Encryption / 4.10.5.3. Retransmissions.
func (s *secureSession) Receive() ([]byte, error) {
	for {
		plaintext, hdr, err := s.receiveOne()
		if errors.Is(err, errForeignSession) {
			log.Debugf("session: %v, waiting for next message", err)
			continue
		}
		if err != nil {
			return nil, err
		}
		protHdr, protHdrErr := message.NewProtocolHeaderFromBytes(plaintext)
		if protHdrErr == nil && protHdr.Opcode().IsMRPStandaloneAck() {
			log.Debugf("session: received standalone MRP ACK, waiting for next message")
			continue
		}
		if protHdrErr == nil && protHdr.IsReliability() {
			if ackErr := s.sendAck(protHdr.ExchangeID(), hdr.MessageCounter(), protHdr.IsInitiator()); ackErr != nil {
				log.Errorf("session: failed to send MRP ack: %v", ackErr)
			}
		}
		return plaintext, nil
	}
}

// receiveOne reads and decrypts exactly one message from the transport,
// returning the decrypted payload along with the parsed (unencrypted)
// message header, which the caller needs to acknowledge the message.
func (s *secureSession) receiveOne() ([]byte, message.Header, error) {
	ctx := context.Background()
	raw, err := s.t.Receive(ctx)
	if err != nil {
		return nil, nil, err
	}
	log.HexDebug(raw)
	if len(raw) < 8 {
		return nil, nil, fmt.Errorf("session: received packet too short (%d bytes)", len(raw))
	}

	// Parse the message header to determine its byte length.
	hdr, err := message.NewHeaderFromBytes(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("session: failed to parse message header: %w", err)
	}

	// A message addressed to this session carries the SessionID this side
	// chose during session establishment (the InitiatorSessionID for the
	// initiator, the ResponderSessionID for the responder — the ID the peer
	// uses when addressing us). Anything else is not part of this session's
	// traffic; decrypting it with this session's keys would only ever fail
	// AES-CCM authentication, so it's rejected here instead.
	if hdr.SessionID() != s.localSessionID() {
		return nil, nil, fmt.Errorf("%w (got %d, want %d)", errForeignSession, hdr.SessionID(), s.localSessionID())
	}

	// Compute the byte length of the header to split header from ciphertext.
	hdrBytes, err := hdr.Bytes()
	if err != nil {
		return nil, nil, fmt.Errorf("session: failed to serialize parsed header: %w", err)
	}
	if len(raw) < len(hdrBytes) {
		return nil, nil, fmt.Errorf("session: packet shorter than header (%d < %d)", len(raw), len(hdrBytes))
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

	// Decrypt with this side's inbound key: R2IKey for the initiator,
	// I2RKey for the responder.
	plaintext, err := crypto.CryptoCCMDecrypt(s.rxKey(), nonce, ciphertextWithTag, hdrBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("session: AES-CCM decryption failed (securityFlags=%#02x, sessionID=%d, msgCounter=%d, hdrLen=%d, rawLen=%d): %w",
			byte(hdr.SecurityFlags()), hdr.SessionID(), msgCounter, len(hdrBytes), len(raw), err)
	}

	log.HexDebug(plaintext)
	return plaintext, hdr, nil
}
