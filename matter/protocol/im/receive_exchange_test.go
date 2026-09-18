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

package im

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/cybergarage/go-matter/matter/encoding/message"
	"github.com/cybergarage/go-matter/matter/protocol/session"
)

// queueSecureSession replays a fixed queue of already-decrypted messages on
// Receive, as if SecureSession had already handled encryption/decryption.
type queueSecureSession struct {
	receives [][]byte
	recvIdx  int
}

func (s *queueSecureSession) Transmit(payload []byte) error { return nil }

func (s *queueSecureSession) Receive() ([]byte, error) {
	if s.recvIdx >= len(s.receives) {
		return nil, fmt.Errorf("queueSecureSession: no more queued messages")
	}
	b := s.receives[s.recvIdx]
	s.recvIdx++
	return b, nil
}

func (s *queueSecureSession) Transport() session.Transport     { return nil }
func (s *queueSecureSession) SessionKeys() session.SessionKeys { return nil }

func buildProtocolHeaderBytes(t *testing.T, exchangeID message.ExchangeID, opcode message.Opcode) []byte {
	t.Helper()
	hdr := message.NewProtocolHeader(
		message.WithHeaderExchangeID(exchangeID),
		message.WithHeaderProtocolID(message.InteractionModel),
		message.WithHeaderOpcode(opcode),
	)
	b, err := hdr.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestReceiveExchangeResponseSkipsMismatchedExchange guards against a
// regression where a real device's late duplicate retransmission of an
// earlier response — sharing this session's SessionID and not itself a
// standalone MRP ack, so neither of SecureSession.Receive's own filters
// caught it — was accepted as the response to a later, unrelated request
// simply because it arrived next. A response only actually answers a
// request if it carries that request's own ExchangeID; anything else must
// be discarded while still waiting for the real one.
func TestReceiveExchangeResponseSkipsMismatchedExchange(t *testing.T) {
	const wantExchangeID = message.ExchangeID(0x1234)
	stray := buildProtocolHeaderBytes(t, 0x9999, message.ReportDataMessage)
	real := buildProtocolHeaderBytes(t, wantExchangeID, message.InvokeResponseMessage)

	sess := &queueSecureSession{receives: [][]byte{stray, real}}

	got, err := receiveExchangeResponse(sess, wantExchangeID)
	if err != nil {
		t.Fatalf("receiveExchangeResponse() error = %v", err)
	}
	if !bytes.Equal(got, real) {
		t.Errorf("receiveExchangeResponse() = %x, want %x (the mismatched-exchange message should have been skipped)", got, real)
	}
	if sess.recvIdx != 2 {
		t.Errorf("Receive() called %d times, want 2 (one skipped, one matched)", sess.recvIdx)
	}
}
