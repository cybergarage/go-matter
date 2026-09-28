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

package pase

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter/crypto"
	"github.com/cybergarage/go-matter/matter/encoding/message"
	"github.com/cybergarage/go-matter/matter/protocol/pase/pake"
	"github.com/cybergarage/go-matter/matter/protocol/pase/pbkdf"
	"github.com/cybergarage/go-matter/matter/types"
)

// DefaultResponderTimeout bounds a whole PASE exchange on the responder side
// when the caller's context has no deadline of its own.
const DefaultResponderTimeout = 60 * time.Second

// ErrUnexpectedMessage is returned when the initiator sends a message the
// PASE exchange does not expect at that point.
var ErrUnexpectedMessage = errors.New("unexpected PASE message")

// Responder is the device side of PASE (Matter Core 4.14.1): it answers an
// initiator's PBKDFParamRequest, runs the SPAKE2+ verifier role with the
// Verifier it was given, and returns the session keys once the initiator
// has proven knowledge of the passcode.
//
// A Responder runs one exchange; create a new one for each attempt.
type Responder struct {
	t           Transport
	verifier    Verifier
	sessionID   SessionID
	established func(SessionKeys)

	counter message.MessageCounter
	// lastPeerCounter and lastSent let the responder answer a retransmitted
	// request with the response it already sent, instead of treating it as
	// a new message.
	lastPeerCounter message.MessageCounter
	hasLastPeer     bool
	lastSent        []byte
}

// ResponderOption configures a Responder.
type ResponderOption func(*Responder)

// WithResponderSessionID sets the session ID the responder offers for the
// new secure session (Matter Core 4.13.2.4). The caller should pick one no
// other active session uses; by default a random non-zero ID different from
// the initiator's is chosen.
func WithResponderSessionID(id SessionID) ResponderOption {
	return func(r *Responder) {
		r.sessionID = id
	}
}

// WithResponderEstablishedHandler sets a function called with the new
// session's keys just before the responder reports success to the
// initiator, which may send its first message on the session as soon as it
// has the report: the caller sets the session up in h so that message
// finds it.
func WithResponderEstablishedHandler(h func(SessionKeys)) ResponderOption {
	return func(r *Responder) {
		r.established = h
	}
}

// NewResponder returns a PASE responder that runs over t and authenticates
// the initiator against verifier.
func NewResponder(t Transport, verifier Verifier, opts ...ResponderOption) *Responder {
	r := &Responder{
		t:               t,
		verifier:        verifier,
		sessionID:       0,
		established:     nil,
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

// EstablishSession waits for a PBKDFParamRequest on the transport and runs
// the exchange to completion. On success the initiator has been sent a
// success StatusReport and the returned keys are those of the new session,
// in the same (initiator-to-responder, responder-to-initiator) form the
// Initiator returns.
//
// If the initiator fails to prove the passcode, or asks for a passcode ID
// other than 0, the responder sends a failure StatusReport and returns an
// error wrapping ErrPASEVerification or ErrUnexpectedMessage.
func (r *Responder) EstablishSession(ctx context.Context) (SessionKeys, error) {
	if err := r.verifier.Validate(); err != nil {
		return nil, err
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, DefaultResponderTimeout)
		defer cancel()
	}

	// 1) PBKDFParamRequest
	reqMsg, reqBytes, err := r.receive(ctx, message.PBKDFParamRequest)
	if err != nil {
		return nil, err
	}
	paramReq, err := pbkdf.NewParamRequestMessageFromBytes(reqBytes)
	if err != nil {
		return nil, fmt.Errorf("pase: decode PBKDFParamRequest: %w", err)
	}
	log.Debugf("PASE responder: PBKDFParamRequest: %s", paramReq.String())
	// 4.14.1.2: passcode ID 0 is the default commissioning passcode, the
	// only one this responder has a verifier for.
	if id := paramReq.PasscodeID(); id != 0 {
		r.sendStatusReport(ctx, reqMsg, statusGeneralFailure, statusProtocolInvalidParameter)
		return nil, fmt.Errorf("%w: passcode ID %d", ErrUnexpectedMessage, id)
	}

	// 2) PBKDFParamResponse. The salt and iteration count are always
	// sent, since they are fixed by the verifier; an initiator that already
	// knows them just receives the same values again.
	sessionID := r.sessionID
	if sessionID == 0 {
		sessionID = types.NewSessionIDExcept(paramReq.InitiatorSessionID())
	}
	paramRes, err := pbkdf.NewParamResponseMessage(
		pbkdf.WithParamResponseMessageParamRequestMessage(paramReq),
		pbkdf.WithParamResponseResponderSessionID(sessionID),
		pbkdf.WithParamResponsePBKDFParams(pbkdf.NewParams(
			pbkdf.WithParamsSalt(r.verifier.Salt),
			pbkdf.WithParamsIterations(r.verifier.Iterations),
		)),
		message.WithHeaderMessageCounter(r.nextCounter()),
	)
	if err != nil {
		return nil, fmt.Errorf("pase: build PBKDFParamResponse: %w", err)
	}
	if err := r.send(ctx, paramRes); err != nil {
		return nil, fmt.Errorf("pase: transmit PBKDFParamResponse: %w", err)
	}

	// 3) Pake1: pA.
	pake1Msg, pake1Bytes, err := r.receive(ctx, message.PASEPake1)
	if err != nil {
		return nil, err
	}
	pake1, err := pake.NewPake1MessageFromBytes(pake1Bytes)
	if err != nil {
		return nil, fmt.Errorf("pase: decode Pake1: %w", err)
	}
	pA := pake1.PA()

	// 4) The verifier's side of SPAKE2+ (Matter Core 3.10): pB, the shared
	// points, the transcript and the confirmation values.
	y, err := crypto.CryptoPAKERandomScalar()
	if err != nil {
		return nil, err
	}
	pB, err := crypto.CryptoPB(y, r.verifier.W0)
	if err != nil {
		return nil, fmt.Errorf("pase: CryptoPB: %w", err)
	}
	z, v, err := crypto.CryptoPAKESharedPointsResponder(y, r.verifier.W0, r.verifier.L, pA)
	if err != nil {
		r.sendStatusReport(ctx, pake1Msg, statusGeneralFailure, statusProtocolInvalidParameter)
		return nil, fmt.Errorf("%w: %w", ErrPASEVerification, err)
	}
	tt, err := crypto.CryptoTranscript(paramReq.Payload(), paramRes.Payload(), pA, pB, z, v, r.verifier.W0)
	if err != nil {
		return nil, fmt.Errorf("pase: CryptoTranscript: %w", err)
	}
	cAExpected, cB, ke, err := crypto.CryptoP2(tt, pA, pB)
	if err != nil {
		return nil, fmt.Errorf("pase: CryptoP2: %w", err)
	}

	// 5) Pake2: pB and cB.
	pake2Opts := []any{
		pake.WithPake2MessagePrecomputed(pB, cB),
		message.WithHeaderExchangeID(pake1Msg.ExchangeID()),
		message.WithHeaderAckCounter(pake1Msg.MessageCounter()),
	}
	for _, opt := range r.replyHeaderOptions(pake1Msg) {
		pake2Opts = append(pake2Opts, opt)
	}
	pake2, err := pake.NewPake2Message(pake2Opts...)
	if err != nil {
		return nil, fmt.Errorf("pase: build Pake2: %w", err)
	}
	if err := r.send(ctx, pake2); err != nil {
		return nil, fmt.Errorf("pase: transmit Pake2: %w", err)
	}

	// 6) Pake3: cA.
	pake3Msg, pake3Bytes, err := r.receive(ctx, message.PASEPake3)
	if err != nil {
		return nil, err
	}
	pake3, err := pake.NewPake3MessageFromBytes(pake3Bytes)
	if err != nil {
		return nil, fmt.Errorf("pase: decode Pake3: %w", err)
	}
	if subtle.ConstantTimeCompare(pake3.CA(), cAExpected) != 1 {
		r.sendStatusReport(ctx, pake3Msg, statusGeneralFailure, statusProtocolInvalidParameter)
		return nil, fmt.Errorf("%w: cA mismatch", ErrPASEVerification)
	}

	// 7) Session keys (Matter Core 4.14.1.3), exactly as the initiator
	// derives them.
	keys, err := crypto.CryptoKDF(ke, nil, []byte("SessionKeys"), 3*CryptoSymmetricKeyLen)
	if err != nil {
		return nil, fmt.Errorf("pase: session key derivation: %w", err)
	}
	sessionKeys := newSessionKeys(
		keys[0:CryptoSymmetricKeyLen],
		keys[CryptoSymmetricKeyLen:2*CryptoSymmetricKeyLen],
		keys[2*CryptoSymmetricKeyLen:3*CryptoSymmetricKeyLen],
		paramReq.InitiatorSessionID(),
		sessionID,
	)
	if r.established != nil {
		r.established(sessionKeys)
	}

	// 8) StatusReport: success.
	if err := r.sendStatusReport(ctx, pake3Msg, statusGeneralSuccess, statusProtocolSessionSuccess); err != nil {
		return nil, fmt.Errorf("pase: transmit StatusReport: %w", err)
	}
	return sessionKeys, nil
}

func (r *Responder) nextCounter() message.MessageCounter {
	c := r.counter
	r.counter = r.counter.Next()
	return c
}

// replyHeaderOptions address a reply to the initiator's ephemeral source
// node ID, when it sent one (Matter Core 4.14.1.2), and give it the
// responder's next message counter.
func (r *Responder) replyHeaderOptions(req message.Message) []message.HeaderOption {
	opts := []message.HeaderOption{message.WithHeaderMessageCounter(r.nextCounter())}
	if src, ok := req.SourceNodeID(); ok {
		opts = append(opts, message.WithHeaderDestinationNodeID(src))
	}
	return opts
}

// receive returns the next message of the exchange, which must carry
// opcode want. Standalone ACKs are skipped. A retransmission of the
// previous request is answered with the response already sent for it.
func (r *Responder) receive(ctx context.Context, want message.Opcode) (message.Message, []byte, error) {
	for {
		b, err := r.t.Receive(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("pase: receive opcode 0x%02X: %w", uint8(want), err)
		}
		msg, err := message.NewMessageFromBytes(b)
		if err != nil {
			return nil, nil, fmt.Errorf("pase: parse message: %w", err)
		}
		if msg.Opcode().IsMRPStandaloneAck() {
			continue
		}
		if r.hasLastPeer && msg.MessageCounter() == r.lastPeerCounter {
			if r.lastSent != nil {
				if err := r.t.Transmit(ctx, r.lastSent); err != nil {
					return nil, nil, fmt.Errorf("pase: retransmit: %w", err)
				}
			}
			continue
		}
		r.lastPeerCounter = msg.MessageCounter()
		r.hasLastPeer = true
		if msg.ProtocolID() == message.SecureChannel && msg.Opcode().IsStatusReport() && want != message.StatusReport {
			// The initiator gave up, typically on a cB it could not verify.
			return nil, nil, fmt.Errorf("%w: the initiator ended the exchange", ErrStatusReport)
		}
		if msg.ProtocolID() != message.SecureChannel || msg.Opcode() != want {
			return nil, nil, fmt.Errorf("%w: got protocol 0x%04X opcode 0x%02X, want opcode 0x%02X", ErrUnexpectedMessage, uint16(msg.ProtocolID()), uint8(msg.Opcode()), uint8(want))
		}
		return msg, b, nil
	}
}

type byteser interface {
	Bytes() ([]byte, error)
}

func (r *Responder) send(ctx context.Context, msg byteser) error {
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
	msg := newStatusReport(req, r.replyHeaderOptions(req), message.ReliabilityFlag|message.AckFlag, generalCode, protocolCode)
	err := r.send(ctx, msg)
	if err != nil && generalCode != statusGeneralSuccess {
		log.Warnf("PASE responder: send failure StatusReport: %v", err)
	}
	return err
}
