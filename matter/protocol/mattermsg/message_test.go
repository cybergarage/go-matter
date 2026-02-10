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

package mattermsg

import (
	"encoding/hex"
	"testing"
)

func TestPacketHeaderEncodeDecodeRoundtrip(t *testing.T) {
	tests := []struct {
		name   string
		header *PacketHeader
	}{
		{
			name: "minimal header without node IDs",
			header: &PacketHeader{
				Flags:          0x00,
				SessionID:      0x0000,
				SecurityFlags:  0x00,
				MessageCounter: 0x12345678,
			},
		},
		{
			name: "header with source node ID",
			header: &PacketHeader{
				Flags:          0x04, // FlagSourceNodeIDPresent
				SessionID:      0x1234,
				SecurityFlags:  0x00,
				MessageCounter: 0xAABBCCDD,
				SourceNodeID:   0x1122334455667788,
			},
		},
		{
			name: "header with both node IDs",
			header: &PacketHeader{
				Flags:          0x05, // FlagSourceNodeIDPresent | FlagDestNodeIDPresent
				SessionID:      0xABCD,
				SecurityFlags:  0x55,
				MessageCounter: 0x11223344,
				SourceNodeID:   0xAABBCCDDEEFF0011,
				DestNodeID:     0x9988776655443322,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode
			encoded := tt.header.Encode()

			// Decode
			decoded, bytesRead, err := DecodePacketHeader(encoded)
			if err != nil {
				t.Fatalf("DecodePacketHeader failed: %v", err)
			}

			if bytesRead != len(encoded) {
				t.Errorf("bytes read mismatch: got %d, want %d", bytesRead, len(encoded))
			}

			// Compare fields
			if decoded.Flags != tt.header.Flags {
				t.Errorf("Flags mismatch: got 0x%02X, want 0x%02X", decoded.Flags, tt.header.Flags)
			}
			if decoded.SessionID != tt.header.SessionID {
				t.Errorf("SessionID mismatch: got 0x%04X, want 0x%04X", decoded.SessionID, tt.header.SessionID)
			}
			if decoded.SecurityFlags != tt.header.SecurityFlags {
				t.Errorf("SecurityFlags mismatch: got 0x%02X, want 0x%02X", decoded.SecurityFlags, tt.header.SecurityFlags)
			}
			if decoded.MessageCounter != tt.header.MessageCounter {
				t.Errorf("MessageCounter mismatch: got 0x%08X, want 0x%08X", decoded.MessageCounter, tt.header.MessageCounter)
			}
			if tt.header.HasSourceNodeID() && decoded.SourceNodeID != tt.header.SourceNodeID {
				t.Errorf("SourceNodeID mismatch: got 0x%016X, want 0x%016X", decoded.SourceNodeID, tt.header.SourceNodeID)
			}
			if tt.header.HasDestNodeID() && decoded.DestNodeID != tt.header.DestNodeID {
				t.Errorf("DestNodeID mismatch: got 0x%016X, want 0x%016X", decoded.DestNodeID, tt.header.DestNodeID)
			}
		})
	}
}

func TestExchangeHeaderEncodeDecodeRoundtrip(t *testing.T) {
	tests := []struct {
		name   string
		header *ExchangeHeader
	}{
		{
			name: "minimal exchange header",
			header: &ExchangeHeader{
				ExchangeFlags: 0x01, // Initiator
				Opcode:        0x20,
				ExchangeID:    0x1234,
				ProtocolID:    0x0000,
			},
		},
		{
			name: "exchange header with reliability flag",
			header: &ExchangeHeader{
				ExchangeFlags: 0x05, // Initiator | Reliability
				Opcode:        0x30,
				ExchangeID:    0xABCD,
				ProtocolID:    0x0001,
			},
		},
		{
			name: "exchange header with ACK",
			header: &ExchangeHeader{
				ExchangeFlags: 0x02, // Ack flag
				Opcode:        0x10,
				ExchangeID:    0x5678,
				ProtocolID:    0x0000,
				AckCounter:    0x11223344,
			},
		},
		{
			name: "exchange header with vendor ID",
			header: &ExchangeHeader{
				ExchangeFlags: 0x11, // Initiator | Vendor
				Opcode:        0x40,
				ExchangeID:    0x9999,
				ProtocolID:    0xFFF1,
				VendorID:      0x1234,
			},
		},
		{
			name: "exchange header with all flags",
			header: &ExchangeHeader{
				ExchangeFlags: 0x1F, // All flags set
				Opcode:        0x50,
				ExchangeID:    0xEEEE,
				ProtocolID:    0x0002,
				VendorID:      0xABCD,
				AckCounter:    0xDEADBEEF,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode
			encoded := tt.header.Encode()

			// Decode
			decoded, bytesRead, err := DecodeExchangeHeader(encoded)
			if err != nil {
				t.Fatalf("DecodeExchangeHeader failed: %v", err)
			}

			if bytesRead != len(encoded) {
				t.Errorf("bytes read mismatch: got %d, want %d", bytesRead, len(encoded))
			}

			// Compare fields
			if decoded.ExchangeFlags != tt.header.ExchangeFlags {
				t.Errorf("ExchangeFlags mismatch: got 0x%02X, want 0x%02X", decoded.ExchangeFlags, tt.header.ExchangeFlags)
			}
			if decoded.Opcode != tt.header.Opcode {
				t.Errorf("Opcode mismatch: got 0x%02X, want 0x%02X", decoded.Opcode, tt.header.Opcode)
			}
			if decoded.ExchangeID != tt.header.ExchangeID {
				t.Errorf("ExchangeID mismatch: got 0x%04X, want 0x%04X", decoded.ExchangeID, tt.header.ExchangeID)
			}
			if decoded.ProtocolID != tt.header.ProtocolID {
				t.Errorf("ProtocolID mismatch: got 0x%04X, want 0x%04X", decoded.ProtocolID, tt.header.ProtocolID)
			}
			if tt.header.HasVendorID() && decoded.VendorID != tt.header.VendorID {
				t.Errorf("VendorID mismatch: got 0x%04X, want 0x%04X", decoded.VendorID, tt.header.VendorID)
			}
			if tt.header.IsAck() && decoded.AckCounter != tt.header.AckCounter {
				t.Errorf("AckCounter mismatch: got 0x%08X, want 0x%08X", decoded.AckCounter, tt.header.AckCounter)
			}
		})
	}
}

func TestMessageEncodeDecodeRoundtrip(t *testing.T) {
	tests := []struct {
		name    string
		message *Message
	}{
		{
			name: "simple message with payload",
			message: &Message{
				PacketHeader: &PacketHeader{
					Flags:          0x00,
					SessionID:      0x0000,
					SecurityFlags:  0x00,
					MessageCounter: 1,
				},
				ExchangeHeader: &ExchangeHeader{
					ExchangeFlags: 0x05, // Initiator | Reliability
					Opcode:        0x20,
					ExchangeID:    0x1234,
					ProtocolID:    0x0000,
				},
				Payload: []byte{0x01, 0x02, 0x03, 0x04},
			},
		},
		{
			name: "message with empty payload",
			message: &Message{
				PacketHeader: &PacketHeader{
					Flags:          0x00,
					SessionID:      0x0000,
					SecurityFlags:  0x00,
					MessageCounter: 2,
				},
				ExchangeHeader: &ExchangeHeader{
					ExchangeFlags: 0x02, // Ack
					Opcode:        0x10,
					ExchangeID:    0x5678,
					ProtocolID:    0x0000,
					AckCounter:    1,
				},
				Payload: []byte{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode
			encoded := tt.message.Encode()

			// Decode
			decoded, err := DecodeMessage(encoded)
			if err != nil {
				t.Fatalf("DecodeMessage failed: %v", err)
			}

			// Compare packet header fields
			if decoded.PacketHeader.MessageCounter != tt.message.PacketHeader.MessageCounter {
				t.Errorf("MessageCounter mismatch: got %d, want %d", decoded.PacketHeader.MessageCounter, tt.message.PacketHeader.MessageCounter)
			}

			// Compare exchange header fields
			if decoded.ExchangeHeader.Opcode != tt.message.ExchangeHeader.Opcode {
				t.Errorf("Opcode mismatch: got 0x%02X, want 0x%02X", decoded.ExchangeHeader.Opcode, tt.message.ExchangeHeader.Opcode)
			}
			if decoded.ExchangeHeader.ExchangeID != tt.message.ExchangeHeader.ExchangeID {
				t.Errorf("ExchangeID mismatch: got 0x%04X, want 0x%04X", decoded.ExchangeHeader.ExchangeID, tt.message.ExchangeHeader.ExchangeID)
			}

			// Compare payload
			if len(decoded.Payload) != len(tt.message.Payload) {
				t.Errorf("Payload length mismatch: got %d, want %d", len(decoded.Payload), len(tt.message.Payload))
			}
			for i := range decoded.Payload {
				if decoded.Payload[i] != tt.message.Payload[i] {
					t.Errorf("Payload byte %d mismatch: got 0x%02X, want 0x%02X", i, decoded.Payload[i], tt.message.Payload[i])
				}
			}
		})
	}
}

// TestDecodeWithCapturedPayload tests decoding with a known captured payload fixture.
// This is a placeholder for when real captured payloads are available.
func TestDecodeWithCapturedPayload(t *testing.T) {
	// Example minimal unsecured message (fabricated for testing, little-endian)
	// PacketHeader: flags=0x00, sessionID=0x0000, securityFlags=0x00, messageCounter=0x00000001
	// ExchangeHeader: flags=0x05 (I|R), opcode=0x20, exchangeID=0x1234, protocolID=0x0000
	// Payload: 0x01 0x02 0x03 0x04
	hexPayload := "00000000" + "01000000" + // Packet header (8 bytes, little-endian)
		"05203412" + "0000" + // Exchange header (6 bytes, little-endian)
		"01020304" // Payload (4 bytes)

	data, err := hex.DecodeString(hexPayload)
	if err != nil {
		t.Fatalf("Failed to decode hex string: %v", err)
	}

	msg, err := DecodeMessage(data)
	if err != nil {
		t.Fatalf("DecodeMessage failed: %v", err)
	}

	// Verify packet header
	if msg.PacketHeader.MessageCounter != 1 {
		t.Errorf("MessageCounter mismatch: got %d, want 1", msg.PacketHeader.MessageCounter)
	}

	// Verify exchange header
	if msg.ExchangeHeader.Opcode != 0x20 {
		t.Errorf("Opcode mismatch: got 0x%02X, want 0x20", msg.ExchangeHeader.Opcode)
	}
	if msg.ExchangeHeader.ExchangeID != 0x1234 {
		t.Errorf("ExchangeID mismatch: got 0x%04X, want 0x1234", msg.ExchangeHeader.ExchangeID)
	}
	if !msg.ExchangeHeader.IsInitiator() {
		t.Error("Expected initiator flag to be set")
	}
	if !msg.ExchangeHeader.IsReliabilityRequested() {
		t.Error("Expected reliability flag to be set")
	}

	// Verify payload
	expectedPayload := []byte{0x01, 0x02, 0x03, 0x04}
	if len(msg.Payload) != len(expectedPayload) {
		t.Errorf("Payload length mismatch: got %d, want %d", len(msg.Payload), len(expectedPayload))
	}
}

func TestPacketHeaderTooShort(t *testing.T) {
	shortData := []byte{0x00, 0x00, 0x00} // Only 3 bytes
	_, _, err := DecodePacketHeader(shortData)
	if err == nil {
		t.Error("Expected error for short packet header, got nil")
	}
}

func TestExchangeHeaderTooShort(t *testing.T) {
	shortData := []byte{0x00, 0x00, 0x00} // Only 3 bytes
	_, _, err := DecodeExchangeHeader(shortData)
	if err == nil {
		t.Error("Expected error for short exchange header, got nil")
	}
}
