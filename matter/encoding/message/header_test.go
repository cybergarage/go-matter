// Copyright (C) 2025 The go-matter Authors. All rights reserved.
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

import (
	"testing"
)

func TestHeaderTooShort(t *testing.T) {
	shortData := []byte{0x00, 0x00, 0x00} // Only 3 bytes
	_, err := NewHeaderFromBytes(shortData)
	if err == nil {
		t.Error("Expected error for short packet header, got nil")
	}
}

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
				WithHeaderFlags(0x04), // FlagSourceNodeIDPresent
				WithHeaderSessionID(0x1234),
				WithHeaderSecurityFlags(0x00),
				WithHeaderMessageCounter(0xAABBCCDD),
				WithHeaderSourceNodeID(0x1122334455667788),
			),
		},
		{
			name: "header with both node IDs",
			header: NewHeader(
				WithHeaderFlags(0x05), // FlagSourceNodeIDPresent | FlagDestNodeIDPresent
				WithHeaderSessionID(0xABCD),
				WithHeaderSecurityFlags(0x55),
				WithHeaderMessageCounter(0x11223344),
				WithHeaderSourceNodeID(0xAABBCCDDEEFF0011),
				WithHeaderDestinationNodeID(0x9988776655443322),
			),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode
			encoded, err := tt.header.Bytes()
			if err != nil {
				t.Fatalf("Header.Bytes failed: %v", err)
			}

			// Decode
			decoded, err := NewHeaderFromBytes(encoded)
			if err != nil {
				t.Fatalf("NewHeaderFromBytes failed: %v", err)
			}

			// Compare fields
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
			headerSrcNodeID, headerHasSrcNodeID := tt.header.SourceNodeID()
			decodedSrcNodeID, decodedHasSrcNodeID := decoded.SourceNodeID()
			if headerHasSrcNodeID && decodedHasSrcNodeID && decodedSrcNodeID != headerSrcNodeID {
				t.Errorf("SourceNodeID mismatch: got 0x%016X, want 0x%016X", decodedSrcNodeID, headerSrcNodeID)
			}
			headerDestNodeID, headerHasDestNodeID := tt.header.DestinationNodeID()
			decodedDestNodeID, decodedHasDestNodeID := decoded.DestinationNodeID()
			if headerHasDestNodeID && decodedHasDestNodeID && decodedDestNodeID != headerDestNodeID {
				t.Errorf("DestNodeID mismatch: got 0x%016X, want 0x%016X", decodedDestNodeID, headerDestNodeID)
			}
		})
	}
}

func TestHeaderGroupDestination(t *testing.T) {
	hdr := NewHeader(
		WithHeaderSessionID(0xB9F7),
		WithHeaderSecurityFlags(0x01),
		WithHeaderMessageCounter(7),
		WithHeaderSourceNodeID(0x1B669),
		WithHeaderGroupID(0x0101),
	)
	b, err := hdr.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 8+8+2 {
		t.Fatalf("a group message header is %d bytes, want 18", len(b))
	}
	decoded, err := NewHeaderFromBytes(append(b, 0xAA))
	if err != nil {
		t.Fatal(err)
	}
	if gid, ok := decoded.GroupID(); !ok || gid != 0x0101 {
		t.Fatalf("GroupID = (%d, %v)", gid, ok)
	}
	if _, ok := decoded.DestinationNodeID(); ok {
		t.Fatal("a group ID read as a destination node ID")
	}
	if src, ok := decoded.SourceNodeID(); !ok || src != 0x1B669 {
		t.Fatalf("SourceNodeID = (0x%X, %v)", src, ok)
	}
}
