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

package message

import "testing"

func TestHeaderEncodeDecodeRoundtrip(t *testing.T) {
	tests := []struct {
		name   string
		header Header
	}{
		{
			name: "minimal header without node IDs",
			header: NewHeader(
				WithHeaderFlags(0x00),
				WithHeaderSessionID(0x0000),
				WithHeaderSecurityFlags(0x00),
				WithHeaderMessageCounter(0x12345678),
			),
		},
		{
			name: "header with source node ID",
			header: NewHeader(
				WithHeaderFlags(FlagSourceNodeIDPresent),
				WithHeaderSessionID(0x1234),
				WithHeaderSecurityFlags(0x00),
				WithHeaderMessageCounter(0xAABBCCDD),
				WithHeaderSourceNodeID(0x1122334455667788),
			),
		},
		{
			name: "header with both node IDs",
			header: NewHeader(
				WithHeaderFlags(FlagSourceNodeIDPresent|FlagDestNodeIDPresent),
				WithHeaderSessionID(0xABCD),
				WithHeaderSecurityFlags(0x55),
				WithHeaderMessageCounter(0x11223344),
				WithHeaderSourceNodeID(0xAABBCCDDEEFF0011),
				WithHeaderDestNodeID(0x9988776655443322),
			),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := tt.header.Encode()

			decoded, bytesRead, err := DecodeHeader(encoded)
			if err != nil {
				t.Fatalf("DecodeHeader failed: %v", err)
			}
			if bytesRead != len(encoded) {
				t.Errorf("bytes read mismatch: got %d, want %d", bytesRead, len(encoded))
			}

			if decoded.Flags() != tt.header.Flags() {
				t.Errorf("Flags mismatch: got 0x%02X, want 0x%02X", decoded.Flags(), tt.header.Flags())
			}
			if decoded.SessionID() != tt.header.SessionID() {
				t.Errorf("SessionID mismatch: got 0x%04X, want 0x%04X", decoded.SessionID(), tt.header.SessionID())
			}
			if decoded.SecurityFlags() != tt.header.SecurityFlags() {
				t.Errorf("SecurityFlags mismatch: got 0x%02X, want 0x%02X", decoded.SecurityFlags(), tt.header.SecurityFlags())
			}
			if decoded.MessageCounter() != tt.header.MessageCounter() {
				t.Errorf("MessageCounter mismatch: got 0x%08X, want 0x%08X", decoded.MessageCounter(), tt.header.MessageCounter())
			}
			if tt.header.HasSourceNodeID() && decoded.SourceNodeID() != tt.header.SourceNodeID() {
				t.Errorf("SourceNodeID mismatch: got 0x%016X, want 0x%016X", decoded.SourceNodeID(), tt.header.SourceNodeID())
			}
			if tt.header.HasDestNodeID() && decoded.DestNodeID() != tt.header.DestNodeID() {
				t.Errorf("DestNodeID mismatch: got 0x%016X, want 0x%016X", decoded.DestNodeID(), tt.header.DestNodeID())
			}
		})
	}
}

func TestFrameEncodeDecodeRoundtrip(t *testing.T) {
	frame := NewFrame(
		NewHeader(
			WithHeaderFlags(0x00),
			WithHeaderSessionID(0x0000),
			WithHeaderSecurityFlags(0x00),
			WithHeaderMessageCounter(1),
		),
		[]byte{0x01, 0x02, 0x03, 0x04},
	)

	encoded := frame.Encode()
	decoded, err := DecodeFrame(encoded)
	if err != nil {
		t.Fatalf("DecodeFrame failed: %v", err)
	}

	if decoded.Header().MessageCounter() != frame.Header().MessageCounter() {
		t.Errorf("MessageCounter mismatch: got %d, want %d", decoded.Header().MessageCounter(), frame.Header().MessageCounter())
	}
	if len(decoded.Payload()) != len(frame.Payload()) {
		t.Errorf("Payload length mismatch: got %d, want %d", len(decoded.Payload()), len(frame.Payload()))
	}
}
