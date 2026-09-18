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

package pase

import (
	"encoding/binary"
	"testing"

	"github.com/cybergarage/go-matter/matter/encoding/message"
)

// buildStatusReportWire builds a StatusReport message with the fixed-width,
// little-endian binary payload the wire protocol actually uses (see
// parseStatusReport's doc comment) — NOT TLV, matching connectedhomeip's
// StatusReport::Parse.
func buildStatusReportWire(t *testing.T, generalCode, protocolCode uint16) []byte {
	t.Helper()
	payload := make([]byte, 8)
	binary.LittleEndian.PutUint16(payload[0:2], generalCode)
	binary.LittleEndian.PutUint32(payload[2:6], uint32(message.SecureChannel))
	binary.LittleEndian.PutUint16(payload[6:8], protocolCode)

	msg := message.NewMessage(
		message.WithMessageFrameHeader(message.NewHeader(
			message.WithHeaderSessionID(0),
			message.WithHeaderSecurityFlags(0x00),
			message.WithHeaderMessageCounter(message.NewMessageCounter()),
		)),
		message.WithMessageProtocolHeader(message.NewProtocolHeader(
			message.WithHeaderExchangeFlags(message.ReliabilityFlag),
			message.WithHeaderOpcode(message.StatusReport),
			message.WithHeaderExchangeID(1),
			message.WithHeaderProtocolID(message.SecureChannel),
		)),
		message.WithMessagePayload(payload),
	)
	wire, err := msg.Bytes()
	if err != nil {
		t.Fatalf("msg.Bytes() error = %v", err)
	}
	return wire
}

// TestParseStatusReportFailure guards against a regression where
// parseStatusReport tried to TLV-decode the StatusReport payload; the real
// wire format is a fixed-width, little-endian binary structure (spec
// 4.11.3 / connectedhomeip StatusReport::Parse), not TLV. Against a real
// device, this made every successful PASE handshake fail at the final step
// with "StatusReport: expected structure, got SignedInt1" — a self-
// consistent TLV-encoded test fixture had masked the bug until then.
func TestParseStatusReportFailure(t *testing.T) {
	i := &Initiator{}
	wire := buildStatusReportWire(t, 1 /* GeneralCode = FAILURE */, 2)
	if err := i.parseStatusReport(wire); err == nil {
		t.Fatal("parseStatusReport(...) error = nil, want non-nil")
	}
}

func TestParseStatusReportSuccess(t *testing.T) {
	i := &Initiator{}
	wire := buildStatusReportWire(t, 0 /* GeneralCode = SUCCESS */, 0)
	if err := i.parseStatusReport(wire); err != nil {
		t.Fatalf("parseStatusReport(...) error = %v, want nil", err)
	}
}
