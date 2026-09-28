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
	"errors"
	"testing"
	"time"

	"github.com/cybergarage/go-matter/matter/crypto"
	"github.com/cybergarage/go-matter/matter/encoding/message"
	"github.com/cybergarage/go-matter/matter/protocol/pase/pake"
	"github.com/cybergarage/go-matter/matter/protocol/pase/pbkdf"
)

const testPasscode = Passcode(20202021)

// pipeTransport is one end of an in-memory, message-preserving pipe.
type pipeTransport struct {
	in  <-chan []byte
	out chan<- []byte
}

func newPipe() (*pipeTransport, *pipeTransport) {
	a2b := make(chan []byte, 16)
	b2a := make(chan []byte, 16)
	return &pipeTransport{in: b2a, out: a2b}, &pipeTransport{in: a2b, out: b2a}
}

func (p *pipeTransport) Transmit(ctx context.Context, b []byte) error {
	select {
	case p.out <- bytes.Clone(b):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *pipeTransport) Receive(ctx context.Context) ([]byte, error) {
	select {
	case b := <-p.in:
		return b, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func testVerifier(t *testing.T, passcode Passcode) Verifier {
	t.Helper()
	v, err := NewVerifier(passcode, bytes.Repeat([]byte{0x5A}, 32), 1000)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

type responderResult struct {
	keys SessionKeys
	err  error
}

func runResponder(ctx context.Context, r *Responder) <-chan responderResult {
	ch := make(chan responderResult, 1)
	go func() {
		keys, err := r.EstablishSession(ctx)
		ch <- responderResult{keys: keys, err: err}
	}()
	return ch
}

func TestResponderEstablishesSessionWithInitiator(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	initT, respT := newPipe()

	done := runResponder(ctx, NewResponder(respT, testVerifier(t, testPasscode), WithResponderSessionID(0x1234)))
	iKeys, err := NewInitiator(initT, testPasscode).EstablishSession(ctx)
	if err != nil {
		t.Fatalf("Initiator.EstablishSession() error = %v", err)
	}
	res := <-done
	if res.err != nil {
		t.Fatalf("Responder.EstablishSession() error = %v", res.err)
	}
	rKeys := res.keys

	if !bytes.Equal(iKeys.I2RKey(), rKeys.I2RKey()) || !bytes.Equal(iKeys.R2IKey(), rKeys.R2IKey()) {
		t.Fatal("initiator and responder derived different session keys")
	}
	if !bytes.Equal(iKeys.AttestationChallenge(), rKeys.AttestationChallenge()) {
		t.Fatal("initiator and responder derived different attestation challenges")
	}
	if bytes.Equal(rKeys.I2RKey(), rKeys.R2IKey()) {
		t.Fatal("I2R and R2I keys are equal")
	}
	if iKeys.InitiatorSessionID() != rKeys.InitiatorSessionID() {
		t.Fatalf("initiator session ID: initiator has %d, responder has %d", iKeys.InitiatorSessionID(), rKeys.InitiatorSessionID())
	}
	if rKeys.ResponderSessionID() != 0x1234 || iKeys.ResponderSessionID() != 0x1234 {
		t.Fatalf("responder session ID = (%d, %d), want 0x1234 on both sides", iKeys.ResponderSessionID(), rKeys.ResponderSessionID())
	}
}

func TestResponderWithWrongPasscode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	initT, respT := newPipe()

	done := runResponder(ctx, NewResponder(respT, testVerifier(t, testPasscode)))
	_, err := NewInitiator(initT, testPasscode+1).EstablishSession(ctx)
	if !errors.Is(err, ErrPASEVerification) {
		t.Fatalf("Initiator.EstablishSession() with a wrong passcode error = %v, want ErrPASEVerification", err)
	}
	// The initiator gives up at cB and says so, so the responder ends the
	// exchange at once rather than waiting for Pake3 until its deadline.
	if res := <-done; !errors.Is(res.err, ErrStatusReport) {
		t.Fatalf("Responder.EstablishSession() error = %v, want ErrStatusReport", res.err)
	}
	if ctx.Err() != nil {
		t.Fatal("the responder only ended at the test deadline")
	}
}

// manualInitiator drives the initiator side by hand so a test can send
// what a real Initiator never would.
type manualInitiator struct {
	t        *testing.T
	ctx      context.Context
	tr       *pipeTransport
	paramReq pbkdf.ParamRequestMessage
	paramRes pbkdf.ParamResponseMessage
}

func (m *manualInitiator) receive() message.Message {
	m.t.Helper()
	b, err := m.tr.Receive(m.ctx)
	if err != nil {
		m.t.Fatal(err)
	}
	msg, err := message.NewMessageFromBytes(b)
	if err != nil {
		m.t.Fatal(err)
	}
	return msg
}

func (m *manualInitiator) sendParamRequest(opts ...any) {
	m.t.Helper()
	req, err := pbkdf.NewParamRequestMessage(opts...)
	if err != nil {
		m.t.Fatal(err)
	}
	b, err := req.Bytes()
	if err != nil {
		m.t.Fatal(err)
	}
	if err := m.tr.Transmit(m.ctx, b); err != nil {
		m.t.Fatal(err)
	}
	m.paramReq = req
}

func TestResponderRejectsWrongCA(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	initT, respT := newPipe()
	done := runResponder(ctx, NewResponder(respT, testVerifier(t, testPasscode)))

	m := &manualInitiator{t: t, ctx: ctx, tr: initT}
	m.sendParamRequest()
	resMsg := m.receive()
	resBytes, _ := resMsg.Bytes()
	paramRes, err := pbkdf.NewParamResponseMessageFromBytes(resBytes)
	if err != nil {
		t.Fatal(err)
	}
	m.paramRes = paramRes

	// Run SPAKE2+ with the wrong passcode, and send cA regardless of cB.
	salt, _ := paramRes.PBKDFParams().Salt()
	iterations, _ := paramRes.PBKDFParams().Iterations()
	w0, w1, err := crypto.CryptoPAKEValuesInitiator((testPasscode + 1).Bytes(), salt, iterations)
	if err != nil {
		t.Fatal(err)
	}
	x, _ := crypto.CryptoPAKERandomScalar()
	pA, _ := crypto.CryptoPA(x, w0)
	pake1Msg, err := pake.NewPake1Message(
		pake.WithPake1MessageParamRequestMessage(m.paramReq),
		pake.WithPake1MessageParamResponseMessage(paramRes),
		pake.WithPake1PA(pA),
	)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := pake1Msg.Bytes()
	if err := initT.Transmit(ctx, b); err != nil {
		t.Fatal(err)
	}
	pake2Bytes, _ := m.receive().Bytes()
	pake2Msg, err := pake.NewPake2MessageFromBytes(pake2Bytes)
	if err != nil {
		t.Fatal(err)
	}
	z, v, err := crypto.CryptoPAKESharedPoints(x, w0, w1, pake2Msg.PB())
	if err != nil {
		t.Fatal(err)
	}
	tt, _ := crypto.CryptoTranscript(m.paramReq.Payload(), paramRes.Payload(), pA, pake2Msg.PB(), z, v, w0)
	// Only cA is needed: this initiator sends it without checking cB.
	cA, _, _, _ := crypto.CryptoP2(tt, pA, pake2Msg.PB()) //nolint:dogsled
	pake3Msg, err := pake.NewPake3Message(
		pake.WithPake3MessageParamRequestMessage(m.paramReq),
		pake.WithPake3MessagePake1Message(pake1Msg),
		pake.WithPake3MessagePake2Message(pake2Msg),
		pake.WithPake3MessagePrecomputedCA(cA),
	)
	if err != nil {
		t.Fatal(err)
	}
	b, _ = pake3Msg.Bytes()
	if err := initT.Transmit(ctx, b); err != nil {
		t.Fatal(err)
	}

	status := m.receive()
	statusBytes, _ := status.Bytes()
	if err := (&Initiator{}).parseStatusReport(statusBytes); !errors.Is(err, ErrStatusReport) {
		t.Fatalf("StatusReport after a wrong cA: parse error = %v, want ErrStatusReport", err)
	}
	if res := <-done; !errors.Is(res.err, ErrPASEVerification) {
		t.Fatalf("Responder.EstablishSession() error = %v, want ErrPASEVerification", res.err)
	}
}

func TestResponderRejectsNonZeroPasscodeID(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	initT, respT := newPipe()
	done := runResponder(ctx, NewResponder(respT, testVerifier(t, testPasscode)))

	m := &manualInitiator{t: t, ctx: ctx, tr: initT}
	m.sendParamRequest(pbkdf.WithParamRequestPasscodeID(1))
	statusBytes, _ := m.receive().Bytes()
	if err := (&Initiator{}).parseStatusReport(statusBytes); !errors.Is(err, ErrStatusReport) {
		t.Fatalf("reply to passcode ID 1: parse error = %v, want a failure StatusReport", err)
	}
	if res := <-done; !errors.Is(res.err, ErrUnexpectedMessage) {
		t.Fatalf("Responder.EstablishSession() error = %v, want ErrUnexpectedMessage", res.err)
	}
}

func TestResponderAnswersRetransmission(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	initT, respT := newPipe()
	rctx, rcancel := context.WithCancel(ctx)
	done := runResponder(rctx, NewResponder(respT, testVerifier(t, testPasscode)))

	m := &manualInitiator{t: t, ctx: ctx, tr: initT}
	m.sendParamRequest()
	first, _ := m.receive().Bytes()
	// The initiator did not get the response and sends the same request
	// again, with the same message counter.
	b, _ := m.paramReq.Bytes()
	if err := initT.Transmit(ctx, b); err != nil {
		t.Fatal(err)
	}
	second, _ := m.receive().Bytes()
	if !bytes.Equal(first, second) {
		t.Fatal("the retransmitted request was not answered with the same PBKDFParamResponse")
	}
	rcancel()
	<-done
}

func TestResponderRejectsUnexpectedOpcode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	initT, respT := newPipe()
	done := runResponder(ctx, NewResponder(respT, testVerifier(t, testPasscode)))

	pake1Msg, err := pake.NewPake1Message(pake.WithPake1PA(bytes.Repeat([]byte{4}, 65)))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := pake1Msg.Bytes()
	if err := initT.Transmit(ctx, b); err != nil {
		t.Fatal(err)
	}
	if res := <-done; !errors.Is(res.err, ErrUnexpectedMessage) {
		t.Fatalf("Responder.EstablishSession() on a Pake1 first error = %v, want ErrUnexpectedMessage", res.err)
	}
}

func TestVerifier(t *testing.T) {
	salt := bytes.Repeat([]byte{1}, 16)
	v, err := NewVerifier(testPasscode, salt, 1000)
	if err != nil {
		t.Fatal(err)
	}
	w0, l, err := crypto.CryptoPAKEValuesResponder(testPasscode.Bytes(), salt, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(v.W0, w0) || !bytes.Equal(v.L, l) {
		t.Fatal("NewVerifier does not match CryptoPAKEValuesResponder")
	}
	if err := v.Validate(); err != nil {
		t.Fatalf("Validate() = %v", err)
	}

	for _, bad := range []struct {
		salt       []byte
		iterations int
	}{
		{salt: bytes.Repeat([]byte{1}, 15), iterations: 1000},
		{salt: bytes.Repeat([]byte{1}, 33), iterations: 1000},
		{salt: salt, iterations: 999},
		{salt: salt, iterations: 100001},
	} {
		if _, err := NewVerifier(testPasscode, bad.salt, bad.iterations); err == nil {
			t.Errorf("NewVerifier(salt %d bytes, %d iterations) = nil error, want an error", len(bad.salt), bad.iterations)
		}
	}

	broken := v
	broken.L = broken.L[:64]
	if err := broken.Validate(); err == nil {
		t.Error("Validate() with a 64-byte L = nil, want an error")
	}

	r, err := NewRandomSaltVerifier(testPasscode, 1000)
	if err != nil || len(r.Salt) != crypto.PBKDBFSaltMax {
		t.Fatalf("NewRandomSaltVerifier() = (salt %d bytes, %v), want a %d-byte salt", len(r.Salt), err, crypto.PBKDBFSaltMax)
	}
}
