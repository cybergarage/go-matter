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

package generalcommissioning

import (
	"testing"

	"github.com/cybergarage/go-matter/matter/encoding/message"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	"github.com/cybergarage/go-matter/matter/protocol/session"
)

type fakeSession struct {
	lastTransmit []byte
	nextReceive  []byte
}

func (s *fakeSession) Transmit(payload []byte) error {
	s.lastTransmit = append([]byte(nil), payload...)
	return nil
}

// Receive echoes s.nextReceive back with its ExchangeID (protocol header
// bytes 2:4, a fixed offset regardless of other header flags) patched to
// match whatever ExchangeID the code under test actually transmitted —
// im.Invoke now rejects any response whose ExchangeID doesn't match its
// request's freshly-generated random one (see im.receiveExchangeResponse),
// so a canned response built with an unrelated ExchangeID would otherwise
// never match and Receive would be called forever.
func (s *fakeSession) Receive() ([]byte, error) {
	resp := append([]byte(nil), s.nextReceive...)
	if len(resp) >= 4 && len(s.lastTransmit) >= 4 {
		copy(resp[2:4], s.lastTransmit[2:4])
	}
	return resp, nil
}
func (s *fakeSession) Transport() session.Transport     { return nil }
func (s *fakeSession) SessionKeys() session.SessionKeys { return nil }

func buildSuccessInvokeResponse(t *testing.T) []byte {
	t.Helper()
	hdr := message.NewProtocolHeader(
		message.WithHeaderExchangeFlags(message.ReliabilityFlag),
		message.WithHeaderOpcode(message.InvokeResponseMessage),
		message.WithHeaderExchangeID(message.NewFirstExchangeID()),
		message.WithHeaderProtocolID(message.InteractionModel),
	)
	hdrBytes, err := hdr.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	enc.PutBool(tlv.NewContextTag(0), false)
	enc.BeginList(tlv.NewContextTag(1))
	enc.BeginStructure(tlv.NewAnonymousTag()) // InvokeResponseIB
	enc.BeginStructure(tlv.NewContextTag(1))  // CommandStatusIB
	enc.BeginStructure(tlv.NewContextTag(0))  // CommandPathIB
	enc.PutUnsigned2(tlv.NewContextTag(0), 0)
	if err := enc.PutUnsigned(tlv.NewContextTag(1), uint64(ClusterID)); err != nil {
		t.Fatal(err)
	}
	if err := enc.PutUnsigned(tlv.NewContextTag(2), 0); err != nil {
		t.Fatal(err)
	}
	if err := enc.EndContainer(); err != nil { // end CommandPathIB
		t.Fatal(err)
	}
	enc.BeginStructure(tlv.NewContextTag(1)) // StatusIB
	enc.PutUnsigned1(tlv.NewContextTag(0), 0)
	if err := enc.EndContainer(); err != nil { // end StatusIB
		t.Fatal(err)
	}
	if err := enc.EndContainer(); err != nil { // end CommandStatusIB
		t.Fatal(err)
	}
	if err := enc.EndContainer(); err != nil { // end InvokeResponseIB
		t.Fatal(err)
	}
	if err := enc.EndContainer(); err != nil { // end invoke-responses
		t.Fatal(err)
	}
	if err := enc.EndContainer(); err != nil { // end top-level
		t.Fatal(err)
	}
	return append(hdrBytes, enc.Bytes()...)
}

// TestArmFailSafeEncodesCommandFieldsAsStructure guards against a regression
// where the shared IM Invoke path wrapped command-fields as an octet string
// instead of embedding them as a literal STRUCTURE (spec 10.7.9), which would
// make every cluster command (not just this one) unparsable by a real
// device's Interaction Model implementation.
func TestArmFailSafeEncodesCommandFieldsAsStructure(t *testing.T) {
	sess := &fakeSession{nextReceive: buildSuccessInvokeResponse(t)}

	if err := ArmFailSafe(sess, 0, 60, 1); err != nil {
		t.Fatalf("ArmFailSafe() error = %v", err)
	}

	hdr, err := message.NewProtocolHeaderFromBytes(sess.lastTransmit)
	if err != nil {
		t.Fatal(err)
	}
	hdrBytes, err := hdr.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	dec := tlv.NewDecoderWithBytes(sess.lastTransmit[len(hdrBytes):])

	var sawCommandFieldsStructure, sawExpiry bool
	depth := 0
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			depth--
			continue
		}
		if ct, ok := elem.Tag().(tlv.ContextTag); ok {
			if ct.ContextNumber() == 1 && depth == 3 && elem.Type().IsStructure() {
				sawCommandFieldsStructure = true
			}
			if ct.ContextNumber() == 0 && depth == 4 {
				if v, ok := elem.Unsigned2(); ok && v == 60 {
					sawExpiry = true
				}
			}
		}
		if elem.Type().IsStructure() || elem.Type().IsList() || elem.Type().IsArray() {
			depth++
		}
	}
	if !sawCommandFieldsStructure {
		t.Error("transmitted request did not encode command-fields as a literal Structure at context tag 1")
	}
	if !sawExpiry {
		t.Error("transmitted request did not contain the expected ExpiryLengthSeconds field")
	}
}
