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

package onoff

import (
	"testing"

	"github.com/cybergarage/go-matter/matter/encoding/message"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	"github.com/cybergarage/go-matter/matter/protocol/session"
)

// fakeSession replays a canned response, patching its ExchangeID to match
// whatever the code under test actually transmitted — see the identical
// pattern in matter/cluster/generalcommissioning/client_test.go.
type fakeSession struct {
	lastTransmit []byte
	nextReceive  []byte
}

func (s *fakeSession) Transmit(payload []byte) error {
	s.lastTransmit = append([]byte(nil), payload...)
	return nil
}

func (s *fakeSession) Receive() ([]byte, error) {
	resp := append([]byte(nil), s.nextReceive...)
	if len(resp) >= 4 && len(s.lastTransmit) >= 4 {
		copy(resp[2:4], s.lastTransmit[2:4])
	}
	return resp, nil
}
func (s *fakeSession) Transport() session.Transport     { return nil }
func (s *fakeSession) SessionKeys() session.SessionKeys { return nil }

func buildInvokeResponse(t *testing.T, commandID uint32, imStatus uint8) []byte {
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
	if err := enc.PutUnsigned(tlv.NewContextTag(2), uint64(commandID)); err != nil {
		t.Fatal(err)
	}
	if err := enc.EndContainer(); err != nil { // end CommandPathIB
		t.Fatal(err)
	}
	enc.BeginStructure(tlv.NewContextTag(1)) // StatusIB
	enc.PutUnsigned1(tlv.NewContextTag(0), imStatus)
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

func buildScalarReportDataMessage(t *testing.T, putData func(enc tlv.Encoder) error) []byte {
	t.Helper()
	hdr := message.NewProtocolHeader(
		message.WithHeaderExchangeFlags(message.ReliabilityFlag),
		message.WithHeaderOpcode(message.ReportDataMessage),
		message.WithHeaderExchangeID(message.NewFirstExchangeID()),
		message.WithHeaderProtocolID(message.InteractionModel),
	)
	hdrBytes, err := hdr.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	enc.BeginArray(tlv.NewContextTag(1))      // attribute-report-IBs
	enc.BeginStructure(tlv.NewAnonymousTag()) // AttributeReportIB
	enc.BeginStructure(tlv.NewContextTag(1))  // AttributeDataIB
	enc.BeginList(tlv.NewContextTag(1))       // AttributePathIB
	enc.PutUnsigned2(tlv.NewContextTag(2), 0)
	if err := enc.EndContainer(); err != nil { // end AttributePathIB
		t.Fatal(err)
	}
	if err := putData(enc); err != nil { // Data (tag 2)
		t.Fatal(err)
	}
	if err := enc.EndContainer(); err != nil { // end AttributeDataIB
		t.Fatal(err)
	}
	if err := enc.EndContainer(); err != nil { // end AttributeReportIB
		t.Fatal(err)
	}
	if err := enc.EndContainer(); err != nil { // end attribute-report-IBs
		t.Fatal(err)
	}
	enc.PutBool(tlv.NewContextTag(4), false) // suppress-response
	if err := enc.EndContainer(); err != nil {
		t.Fatal(err)
	}

	return append(hdrBytes, enc.Bytes()...)
}

func TestOn(t *testing.T) {
	sess := &fakeSession{nextReceive: buildInvokeResponse(t, uint32(OnCommandID), 0)}
	if err := On(sess, 1); err != nil {
		t.Fatalf("On() error = %v", err)
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
	var sawOnCommandID bool
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			continue
		}
		if ct, ok := elem.Tag().(tlv.ContextTag); ok && ct.ContextNumber() == 2 {
			if v, ok := elem.Unsigned(); ok && v == uint64(OnCommandID) {
				sawOnCommandID = true
			}
		}
	}
	if !sawOnCommandID {
		t.Error("transmitted request did not carry the On command ID (0x01)")
	}
}

func TestOff(t *testing.T) {
	sess := &fakeSession{nextReceive: buildInvokeResponse(t, uint32(OffCommandID), 0)}
	if err := Off(sess, 1); err != nil {
		t.Fatalf("Off() error = %v", err)
	}
}

func TestToggle(t *testing.T) {
	sess := &fakeSession{nextReceive: buildInvokeResponse(t, uint32(ToggleCommandID), 0)}
	if err := Toggle(sess, 1); err != nil {
		t.Fatalf("Toggle() error = %v", err)
	}
}

func TestOnFailureStatus(t *testing.T) {
	sess := &fakeSession{nextReceive: buildInvokeResponse(t, uint32(OnCommandID), 0x87)}
	err := On(sess, 1)
	if err == nil {
		t.Fatal("On() error = nil, want non-nil for a failure status")
	}
}

func TestOnOff(t *testing.T) {
	data := buildScalarReportDataMessage(t, func(enc tlv.Encoder) error {
		enc.PutBool(tlv.NewContextTag(2), true)
		return nil
	})
	sess := &fakeSession{nextReceive: data}

	got, err := OnOff(sess, 1)
	if err != nil {
		t.Fatalf("OnOff() error = %v", err)
	}
	if !got {
		t.Errorf("OnOff() = %v, want true", got)
	}
}

func TestOnOffAttributeStatusError(t *testing.T) {
	hdr := message.NewProtocolHeader(
		message.WithHeaderExchangeFlags(message.ReliabilityFlag),
		message.WithHeaderOpcode(message.ReportDataMessage),
		message.WithHeaderExchangeID(message.NewFirstExchangeID()),
		message.WithHeaderProtocolID(message.InteractionModel),
	)
	hdrBytes, err := hdr.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	enc.BeginArray(tlv.NewContextTag(1))      // attribute-report-IBs
	enc.BeginStructure(tlv.NewAnonymousTag()) // AttributeReportIB
	enc.BeginStructure(tlv.NewContextTag(0))  // AttributeStatusIB
	enc.BeginList(tlv.NewContextTag(0))       // AttributePathIB
	enc.PutUnsigned2(tlv.NewContextTag(2), 0)
	if err := enc.EndContainer(); err != nil {
		t.Fatal(err)
	}
	enc.BeginStructure(tlv.NewContextTag(1))     // StatusIB
	enc.PutUnsigned1(tlv.NewContextTag(0), 0x8b) // UnsupportedAttribute
	if err := enc.EndContainer(); err != nil {
		t.Fatal(err)
	}
	if err := enc.EndContainer(); err != nil { // end AttributeStatusIB
		t.Fatal(err)
	}
	if err := enc.EndContainer(); err != nil { // end AttributeReportIB
		t.Fatal(err)
	}
	if err := enc.EndContainer(); err != nil { // end attribute-report-IBs
		t.Fatal(err)
	}
	enc.PutBool(tlv.NewContextTag(4), false)
	if err := enc.EndContainer(); err != nil {
		t.Fatal(err)
	}
	data := append(append([]byte{}, hdrBytes...), enc.Bytes()...)

	sess := &fakeSession{nextReceive: data}
	if _, err := OnOff(sess, 1); err == nil {
		t.Fatal("OnOff() error = nil, want non-nil for an AttributeStatusIB report")
	}
}
