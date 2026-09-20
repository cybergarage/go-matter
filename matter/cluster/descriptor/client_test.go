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

package descriptor

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

func buildListReportDataMessage(t *testing.T, buildData func(enc tlv.Encoder)) []byte {
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
	enc.BeginArray(tlv.NewContextTag(2)) // Data
	buildData(enc)
	if err := enc.EndContainer(); err != nil { // end Data
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

func TestServerList(t *testing.T) {
	data := buildListReportDataMessage(t, func(enc tlv.Encoder) {
		enc.PutUnsigned4(tlv.NewAnonymousTag(), 0x001D)
		enc.PutUnsigned4(tlv.NewAnonymousTag(), 0x0028)
	})
	sess := &fakeSession{nextReceive: data}

	got, err := ServerList(sess, 0)
	if err != nil {
		t.Fatalf("ServerList() error = %v", err)
	}
	want := []uint32{0x001D, 0x0028}
	if len(got) != len(want) {
		t.Fatalf("ServerList() = %v, want %v", got, want)
	}
	for i := range want {
		if uint32(got[i]) != want[i] {
			t.Errorf("ServerList()[%d] = %#x, want %#x", i, got[i], want[i])
		}
	}
}

func TestPartsList(t *testing.T) {
	data := buildListReportDataMessage(t, func(enc tlv.Encoder) {
		enc.PutUnsigned2(tlv.NewAnonymousTag(), 1)
		enc.PutUnsigned2(tlv.NewAnonymousTag(), 2)
	})
	sess := &fakeSession{nextReceive: data}

	got, err := PartsList(sess, 0)
	if err != nil {
		t.Fatalf("PartsList() error = %v", err)
	}
	want := []uint16{1, 2}
	if len(got) != len(want) {
		t.Fatalf("PartsList() = %v, want %v", got, want)
	}
	for i := range want {
		if uint16(got[i]) != want[i] {
			t.Errorf("PartsList()[%d] = %v, want %v", i, got[i], want[i])
		}
	}
}

func TestDeviceTypeList(t *testing.T) {
	data := buildListReportDataMessage(t, func(enc tlv.Encoder) {
		enc.BeginStructure(tlv.NewAnonymousTag()) // DeviceTypeStruct
		enc.PutUnsigned4(tlv.NewContextTag(0), 0x0100)
		enc.PutUnsigned2(tlv.NewContextTag(1), 1)
		if err := enc.EndContainer(); err != nil {
			t.Fatal(err)
		}
	})
	sess := &fakeSession{nextReceive: data}

	got, err := DeviceTypeList(sess, 0)
	if err != nil {
		t.Fatalf("DeviceTypeList() error = %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("DeviceTypeList() = %+v, want 1 entry", got)
	}
	if got[0].DeviceType != 0x0100 || got[0].Revision != 1 {
		t.Errorf("DeviceTypeList()[0] = %+v, want {DeviceType:0x100 Revision:1}", got[0])
	}
}

func TestServerListAttributeStatusError(t *testing.T) {
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
	if _, err := ServerList(sess, 0); err == nil {
		t.Fatal("ServerList() error = nil, want non-nil for an AttributeStatusIB report")
	}
}
