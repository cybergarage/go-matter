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

package basicinformation

import (
	"testing"

	"github.com/cybergarage/go-matter/matter/encoding/message"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	"github.com/cybergarage/go-matter/matter/protocol/session"
)

// fakeSession replays a canned ReadResponse, patching its ExchangeID to
// match whatever the code under test actually transmitted — see the
// identical pattern in matter/cluster/generalcommissioning/client_test.go.
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

func TestVendorID(t *testing.T) {
	data := buildScalarReportDataMessage(t, func(enc tlv.Encoder) error {
		enc.PutUnsigned2(tlv.NewContextTag(2), 0xFFF1)
		return nil
	})
	sess := &fakeSession{nextReceive: data}

	got, err := VendorID(sess, 0)
	if err != nil {
		t.Fatalf("VendorID() error = %v", err)
	}
	if got != 0xFFF1 {
		t.Errorf("VendorID() = %#x, want 0xFFF1", got)
	}
}

func TestProductID(t *testing.T) {
	data := buildScalarReportDataMessage(t, func(enc tlv.Encoder) error {
		enc.PutUnsigned2(tlv.NewContextTag(2), 0x8000)
		return nil
	})
	sess := &fakeSession{nextReceive: data}

	got, err := ProductID(sess, 0)
	if err != nil {
		t.Fatalf("ProductID() error = %v", err)
	}
	if got != 0x8000 {
		t.Errorf("ProductID() = %#x, want 0x8000", got)
	}
}

func TestVendorName(t *testing.T) {
	data := buildScalarReportDataMessage(t, func(enc tlv.Encoder) error {
		return enc.PutUTF81(tlv.NewContextTag(2), "Acme")
	})
	sess := &fakeSession{nextReceive: data}

	got, err := VendorName(sess, 0)
	if err != nil {
		t.Fatalf("VendorName() error = %v", err)
	}
	if got != "Acme" {
		t.Errorf("VendorName() = %q, want %q", got, "Acme")
	}
}

func TestSoftwareVersion(t *testing.T) {
	data := buildScalarReportDataMessage(t, func(enc tlv.Encoder) error {
		enc.PutUnsigned4(tlv.NewContextTag(2), 0x00010203)
		return nil
	})
	sess := &fakeSession{nextReceive: data}

	got, err := SoftwareVersion(sess, 0)
	if err != nil {
		t.Fatalf("SoftwareVersion() error = %v", err)
	}
	if got != 0x00010203 {
		t.Errorf("SoftwareVersion() = %#x, want 0x00010203", got)
	}
}

func TestVendorIDAttributeStatusError(t *testing.T) {
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
	if _, err := VendorID(sess, 0); err == nil {
		t.Fatal("VendorID() error = nil, want non-nil for an AttributeStatusIB report")
	}
}
