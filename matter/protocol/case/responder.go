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

package caseprotocol

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter/credentials"
	mcrypto "github.com/cybergarage/go-matter/matter/crypto"
	"github.com/cybergarage/go-matter/matter/encoding/message"
	"github.com/cybergarage/go-matter/matter/protocol/session"
	"github.com/cybergarage/go-matter/matter/types"
)

// DefaultResponderTimeout bounds a whole CASE exchange on the responder side
// when the caller's context has no deadline of its own.
const DefaultResponderTimeout = 60 * time.Second

// Secure Channel status codes a CASE responder reports with (Matter Core
// 4.11.1.3).
const (
	statusGeneralSuccess           uint16 = 0
	statusGeneralFailure           uint16 = 1
	statusProtocolSessionSuccess   uint16 = 0x0000
	statusProtocolNoSharedRoot     uint16 = 0x0001
	statusProtocolInvalidParameter uint16 = 0x0002
)

var (
	// ErrNoSharedTrustRoot is returned when the Sigma1 destination names
	// no fabric the responder is on.
	ErrNoSharedTrustRoot = errors.New("case: no shared trust root")
	// ErrUnexpectedMessage is returned when the initiator sends a message
	// the CASE exchange does not expect at that point.
	ErrUnexpectedMessage = errors.New("case: unexpected message")
	// ErrInvalidInitiator is returned when the initiator's Sigma3 does not
	// prove its identity on the fabric.
	ErrInvalidInitiator = errors.New("case: invalid initiator credentials")
)

// ResponderFabric is one fabric a CASE responder can be reached on: its
// identity on the fabric and the credentials it proves it with.
type ResponderFabric struct {
	// FabricIndex is the device's index of the fabric, reported back in
	// ResponderSession.
	FabricIndex uint8
	FabricID    uint64
	NodeID      uint64
	// RootPublicKey is the fabric's root public key, uncompressed.
	RootPublicKey []byte
	// RCAC, ICAC and NOC are the fabric's certificates in the Matter TLV
	// encoding. ICAC is empty when the NOC is issued by the root.
	RCAC []byte
	ICAC []byte
	NOC  []byte
	// IPK is the fabric's Identity Protection Key epoch key, as AddNOC
	// delivered it; the operational key is derived from it.
	IPK []byte
	// Signer signs with the NOC's private key.
	Signer credentials.Signer
}

// ResponderSession is a CASE session a Responder established.
type ResponderSession struct {
	// Keys are the session keys, with this node as the local node and the
	// initiator as the peer.
	Keys session.SessionKeys
	// FabricIndex is the index of the fabric the session is on.
	FabricIndex uint8
	// PeerNodeID is the initiator's node ID, from its NOC.
	PeerNodeID uint64
	// PeerCATs are the CASE Authenticated Tags in the initiator's NOC.
	PeerCATs []uint32
}

// ResponderOption configures a Responder.
type ResponderOption func(*Responder)

// WithResponderSessionID sets the session ID the responder offers for the
// new secure session. The caller should pick one no other active session
// uses; by default a random non-zero ID is chosen.
func WithResponderSessionID(id session.SessionID) ResponderOption {
	return func(r *Responder) {
		r.sessionID = id
	}
}

// Responder is the device side of CASE (Matter Core 4.14.2): it answers a
// Sigma1 addressed to one of its fabrics, proves its identity on that
// fabric in Sigma2, and checks the initiator's in Sigma3. Session
// resumption is not supported: a Sigma1 asking to resume gets a full
// Sigma2.
//
// A Responder runs one exchange; create a new one for each attempt.
type Responder struct {
	t         Transport
	fabrics   func() ([]ResponderFabric, error)
	sessionID session.SessionID

	counter         message.MessageCounter
	lastPeerCounter message.MessageCounter
	hasLastPeer     bool
	lastSent        []byte
}

// NewResponder returns a CASE responder that runs over t and looks up the
// fabric a Sigma1 is for with fabrics.
func NewResponder(t Transport, fabrics func() ([]ResponderFabric, error), opts ...ResponderOption) *Responder {
	r := &Responder{
		t:               t,
		fabrics:         fabrics,
		sessionID:       0,
		counter:         message.NewMessageCounter(),
		lastPeerCounter: 0,
		hasLastPeer:     false,
		lastSent:        nil,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// EstablishSession waits for a Sigma1 on the transport and runs the
// exchange to completion. On success the initiator has been sent a
// success StatusReport. When the Sigma1 names no fabric of the responder,
// or Sigma3 does not verify, the responder sends a failure StatusReport and
// returns an error wrapping ErrNoSharedTrustRoot or ErrInvalidInitiator.
func (r *Responder) EstablishSession(ctx context.Context) (*ResponderSession, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, DefaultResponderTimeout)
		defer cancel()
	}

	// 1) Sigma1: find the fabric its destination ID names.
	sigma1Msg, err := r.receive(ctx, message.CASESigma1)
	if err != nil {
		return nil, err
	}
	s1, err := decodeSigma1(sigma1Msg.Payload())
	if err != nil {
		r.sendStatusReport(ctx, sigma1Msg, statusGeneralFailure, statusProtocolInvalidParameter)
		return nil, err
	}
	fabric, ipk, err := r.findFabric(s1)
	if err != nil {
		code := statusProtocolInvalidParameter
		if errors.Is(err, ErrNoSharedTrustRoot) {
			code = statusProtocolNoSharedRoot
		}
		r.sendStatusReport(ctx, sigma1Msg, statusGeneralFailure, code)
		return nil, err
	}

	// 2) Sigma2: prove this node's identity on the fabric.
	sessionID := r.sessionID
	if sessionID == 0 {
		sessionID = types.NewSessionIDExcept(types.SessionID(s1.InitiatorSessionID))
	}
	ephPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("case: responder ephemeral key: %w", err)
	}
	ephPub, err := ephPriv.PublicKey.ECDH()
	if err != nil {
		return nil, err
	}
	responderEphPubKey := ephPub.Bytes()
	sharedSecret, err := ecdhSharedSecret(ephPriv, s1.InitiatorEphPubKey)
	if err != nil {
		r.sendStatusReport(ctx, sigma1Msg, statusGeneralFailure, statusProtocolInvalidParameter)
		return nil, err
	}
	responderRandom := make([]byte, randomLen)
	if _, err := rand.Read(responderRandom); err != nil {
		return nil, err
	}
	resumptionID := make([]byte, resumptionIDLen)
	if _, err := rand.Read(resumptionID); err != nil {
		return nil, err
	}
	tbs2, err := encodeSigmaTBSData(fabric.NOC, fabric.ICAC, responderEphPubKey, s1.InitiatorEphPubKey)
	if err != nil {
		return nil, err
	}
	sig2, err := fabric.Signer.Sign(tbs2)
	if err != nil {
		return nil, fmt.Errorf("case: Sigma2 signature: %w", err)
	}
	tbe2, err := encodeSigma2TBEData(sigma2TBEData{
		ResponderNOC:  fabric.NOC,
		ResponderICAC: fabric.ICAC,
		Signature:     sig2,
		ResumptionID:  resumptionID,
	})
	if err != nil {
		return nil, err
	}
	s2k, err := deriveSigma2Key(sharedSecret, ipk, responderRandom, responderEphPubKey, sigma1Msg.Payload())
	if err != nil {
		return nil, err
	}
	encrypted2, err := mcrypto.CryptoCCMEncrypt(s2k, sigma2Nonce, tbe2, nil)
	if err != nil {
		return nil, fmt.Errorf("case: encrypt Sigma2 payload: %w", err)
	}
	sigma2Payload, err := encodeSigma2(sigma2{
		ResponderRandom:    responderRandom,
		ResponderSessionID: uint16(sessionID),
		ResponderEphPubKey: responderEphPubKey,
		Encrypted2:         encrypted2,
	})
	if err != nil {
		return nil, err
	}
	if err := r.reply(ctx, sigma1Msg, message.CASESigma2, sigma2Payload); err != nil {
		return nil, fmt.Errorf("case: transmit Sigma2: %w", err)
	}

	// 3) Sigma3: check the initiator's identity on the same fabric.
	sigma3Msg, err := r.receive(ctx, message.CASESigma3)
	if err != nil {
		return nil, err
	}
	peer, err := r.verifySigma3(sigma3Msg.Payload(), fabric, sharedSecret, ipk, sigma1Msg.Payload(), sigma2Payload, s1.InitiatorEphPubKey, responderEphPubKey)
	if err != nil {
		r.sendStatusReport(ctx, sigma3Msg, statusGeneralFailure, statusProtocolInvalidParameter)
		return nil, err
	}

	// 4) SigmaFinished.
	if err := r.sendStatusReport(ctx, sigma3Msg, statusGeneralSuccess, statusProtocolSessionSuccess); err != nil {
		return nil, fmt.Errorf("case: transmit StatusReport: %w", err)
	}

	keys, err := deriveSessionKeys(sharedSecret, ipk, sigma1Msg.Payload(), sigma2Payload, sigma3Msg.Payload(),
		session.SessionID(s1.InitiatorSessionID), sessionID, session.NodeID(fabric.NodeID), session.NodeID(peer.NodeID))
	if err != nil {
		return nil, err
	}
	return &ResponderSession{
		Keys:        keys,
		FabricIndex: fabric.FabricIndex,
		PeerNodeID:  peer.NodeID,
		PeerCATs:    peer.CATs,
	}, nil
}

// findFabric returns the fabric whose destination ID (Matter Core
// 4.14.2.4) Sigma1 carries, and its operational IPK.
func (r *Responder) findFabric(s1 sigma1) (ResponderFabric, []byte, error) {
	fabrics, err := r.fabrics()
	if err != nil {
		return ResponderFabric{}, nil, fmt.Errorf("case: list fabrics: %w", err)
	}
	for _, f := range fabrics {
		compressed, err := computeCompressedFabricIDBytes(f.RootPublicKey, f.FabricID)
		if err != nil {
			log.Warnf("case: fabric %d: %v", f.FabricIndex, err)
			continue
		}
		ipk, err := deriveGroupOperationalKey(f.IPK, compressed)
		if err != nil {
			log.Warnf("case: fabric %d: %v", f.FabricIndex, err)
			continue
		}
		candidate := computeDestinationID(ipk, s1.InitiatorRandom, f.RootPublicKey, f.FabricID, f.NodeID)
		if hmac.Equal(candidate, s1.DestinationID) {
			return f, ipk, nil
		}
	}
	return ResponderFabric{}, nil, ErrNoSharedTrustRoot
}

// verifySigma3 decrypts Sigma3 and checks the initiator's NOC chains to
// the fabric's root and its signature over the exchange. It returns the
// initiator's NOC.
func (r *Responder) verifySigma3(payload []byte, fabric ResponderFabric, sharedSecret, ipk, sigma1Payload, sigma2Payload, initiatorEphPubKey, responderEphPubKey []byte) (*credentials.OperationalCertificate, error) {
	s3, err := decodeSigma3(payload)
	if err != nil {
		return nil, err
	}
	s3k, err := deriveSigma3Key(sharedSecret, ipk, sigma1Payload, sigma2Payload)
	if err != nil {
		return nil, err
	}
	tbe3Bytes, err := mcrypto.CryptoCCMDecrypt(s3k, sigma3Nonce, s3.Encrypted3, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: decrypt Sigma3: %w", ErrInvalidInitiator, err)
	}
	tbe3, err := decodeSigma3TBEData(tbe3Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidInitiator, err)
	}
	rcac, err := credentials.ParseOperationalCertificate(fabric.RCAC)
	if err != nil {
		return nil, fmt.Errorf("case: fabric %d root: %w", fabric.FabricIndex, err)
	}
	noc, err := credentials.ParseOperationalCertificate(tbe3.InitiatorNOC)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidInitiator, err)
	}
	var icac *credentials.OperationalCertificate
	if len(tbe3.InitiatorICAC) != 0 {
		if icac, err = credentials.ParseOperationalCertificate(tbe3.InitiatorICAC); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidInitiator, err)
		}
	}
	if err := credentials.VerifyOperationalChain(noc, icac, rcac); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidInitiator, err)
	}
	if noc.FabricID != fabric.FabricID {
		return nil, fmt.Errorf("%w: the initiator is on fabric 0x%016X, not 0x%016X", ErrInvalidInitiator, noc.FabricID, fabric.FabricID)
	}
	tbs3, err := encodeSigmaTBSData(tbe3.InitiatorNOC, tbe3.InitiatorICAC, initiatorEphPubKey, responderEphPubKey)
	if err != nil {
		return nil, err
	}
	pub, ok := noc.Certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: the NOC key is not ECDSA", ErrInvalidInitiator)
	}
	if err := credentials.VerifySignature(pub, tbs3, tbe3.Signature); err != nil {
		return nil, fmt.Errorf("%w: Sigma3 signature: %w", ErrInvalidInitiator, err)
	}
	return noc, nil
}

func (r *Responder) nextCounter() message.MessageCounter {
	c := r.counter
	r.counter = r.counter.Next()
	return c
}

// receive returns the next message of the exchange, which must carry
// opcode want. Standalone ACKs are skipped, and a retransmission of the
// previous request is answered with the response already sent for it.
func (r *Responder) receive(ctx context.Context, want message.Opcode) (message.Message, error) {
	for {
		b, err := r.t.Receive(ctx)
		if err != nil {
			return nil, fmt.Errorf("case: receive opcode 0x%02X: %w", uint8(want), err)
		}
		msg, err := message.NewMessageFromBytes(b)
		if err != nil {
			return nil, fmt.Errorf("case: parse message: %w", err)
		}
		if msg.Opcode().IsMRPStandaloneAck() {
			continue
		}
		if r.hasLastPeer && msg.MessageCounter() == r.lastPeerCounter {
			if r.lastSent != nil {
				if err := r.t.Transmit(ctx, r.lastSent); err != nil {
					return nil, fmt.Errorf("case: retransmit: %w", err)
				}
			}
			continue
		}
		r.lastPeerCounter = msg.MessageCounter()
		r.hasLastPeer = true
		if msg.ProtocolID() == message.SecureChannel && msg.Opcode().IsStatusReport() {
			if sr, err := decodeStatusReport(msg); err == nil {
				return nil, fmt.Errorf("%w: the initiator ended the exchange: %s", errStatusReport, sr)
			}
			return nil, fmt.Errorf("%w: the initiator ended the exchange", errStatusReport)
		}
		if msg.ProtocolID() != message.SecureChannel || msg.Opcode() != want {
			return nil, fmt.Errorf("%w: got protocol 0x%04X opcode 0x%02X, want opcode 0x%02X", ErrUnexpectedMessage, uint16(msg.ProtocolID()), uint8(msg.Opcode()), uint8(want))
		}
		return msg, nil
	}
}

// reply sends a Secure Channel message answering req on its exchange: not
// as the initiator, acknowledging req and asking for an ack, and addressed
// to req's source node ID when it has one.
func (r *Responder) reply(ctx context.Context, req message.Message, opcode message.Opcode, payload []byte) error {
	headerOpts := []message.HeaderOption{
		message.WithHeaderSessionID(0),
		message.WithHeaderSecurityFlags(0x00),
		message.WithHeaderMessageCounter(r.nextCounter()),
	}
	if src, ok := req.SourceNodeID(); ok {
		headerOpts = append(headerOpts, message.WithHeaderDestinationNodeID(src))
	}
	msg := message.NewMessage(
		message.WithMessageFrameHeader(message.NewHeader(headerOpts...)),
		message.WithMessageProtocolHeader(message.NewProtocolHeader(
			message.WithHeaderExchangeFlags(message.ReliabilityFlag),
			message.WithHeaderOpcode(opcode),
			message.WithHeaderExchangeID(req.ExchangeID()),
			message.WithHeaderProtocolID(message.SecureChannel),
			message.WithHeaderAckCounter(req.MessageCounter()),
		)),
		message.WithMessagePayload(payload),
	)
	b, err := msg.Bytes()
	if err != nil {
		return err
	}
	r.lastSent = bytes.Clone(b)
	return r.t.Transmit(ctx, b)
}

// sendStatusReport answers req with a StatusReport. A failure to send a
// failure report is only logged: the exchange is failing anyway, and the
// caller reports the original cause.
func (r *Responder) sendStatusReport(ctx context.Context, req message.Message, generalCode, protocolCode uint16) error {
	payload := make([]byte, statusReportHeaderLen)
	binary.LittleEndian.PutUint16(payload[0:2], generalCode)
	binary.LittleEndian.PutUint32(payload[2:6], uint32(message.SecureChannel))
	binary.LittleEndian.PutUint16(payload[6:8], protocolCode)
	err := r.reply(ctx, req, message.StatusReport, payload)
	if err != nil && generalCode != statusGeneralSuccess {
		log.Warnf("CASE responder: send failure StatusReport: %v", err)
	}
	return err
}
