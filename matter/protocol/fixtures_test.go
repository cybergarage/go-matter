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

package protocol

import (
	"encoding/hex"
	"testing"
)

// TestDecodeRealWorldPayloads tests decoding with example payloads
// that approximate real Matter message structures.
func TestDecodeRealWorldPayloads(t *testing.T) {
	tests := []struct {
		name         string
		hexPayload   string
		expectError  bool
		validateFunc func(*testing.T, *Message)
		description  string
	}{
		{
			name:        "PBKDFParamRequest-like message",
			description: "Unsecured message with reliability flag requesting PBKDF parameters",
			// Packet header: version=0, no node IDs, sessionID=0, securityFlags=0, msgCtr=1
			// Exchange header: I|R flags, opcode=0x20, exchangeID=0x1234, protocolID=0x0000 (SecureChannel)
			// Payload: minimal TLV structure
			hexPayload: "00" + "0000" + "00" + "01000000" + // Packet header (8 bytes)
				"05" + "20" + "3412" + "0000" + // Exchange header (6 bytes)
				"153001", // Payload (sample TLV: 0x15 = struct, 0x30 = element, 0x01 = end)
			validateFunc: func(t *testing.T, msg *Message) {
				t.Helper()
				if msg.SessionID() != 0x0000 {
					t.Errorf("Expected sessionID 0x0000, got 0x%04X", msg.SessionID())
				}
				if !msg.ExchangeHeader.IsInitiator() {
					t.Error("Expected initiator flag to be set")
				}
				if !msg.ExchangeHeader.IsReliabilityRequested() {
					t.Error("Expected reliability flag to be set")
				}
				if msg.ExchangeHeader.Opcode != 0x20 {
					t.Errorf("Expected opcode 0x20, got 0x%02X", msg.ExchangeHeader.Opcode)
				}
				if msg.ExchangeHeader.ProtocolID != 0x0000 {
					t.Errorf("Expected protocolID 0x0000 (SecureChannel), got 0x%04X", msg.ExchangeHeader.ProtocolID)
				}
			},
		},
		{
			name:        "Standalone ACK message",
			description: "ACK message with ack counter",
			// Packet header: version=0, sessionID=0x1234, msgCtr=100
			// Exchange header: A flag, opcode=0x00, exchangeID=0x5678, ackCounter=42
			hexPayload: "00" + "3412" + "00" + "64000000" + // Packet header
				"02" + "00" + "7856" + "0000" + "2a000000" + // Exchange header with ACK (10 bytes)
				"", // No payload
			validateFunc: func(t *testing.T, msg *Message) {
				t.Helper()
				if !msg.ExchangeHeader.IsAck() {
					t.Error("Expected ACK flag to be set")
				}
				if msg.ExchangeHeader.AckCounter != 42 {
					t.Errorf("Expected ackCounter 42, got %d", msg.ExchangeHeader.AckCounter)
				}
				if msg.MessageCounter() != 100 {
					t.Errorf("Expected messageCounter 100, got %d", msg.MessageCounter())
				}
				if len(msg.Payload) != 0 {
					t.Errorf("Expected empty payload for standalone ACK, got %d bytes", len(msg.Payload))
				}
			},
		},
		{
			name:        "Message with vendor protocol",
			description: "Message using vendor-specific protocol",
			// Exchange header with V flag and vendor ID
			hexPayload: "00" + "0000" + "00" + "01000000" + // Packet header
				"11" + "40" + "9999" + "f1ff" + "3412" + // Exchange header with V flag (8 bytes)
				"aabbcc", // Sample payload
			validateFunc: func(t *testing.T, msg *Message) {
				t.Helper()
				if !msg.ExchangeHeader.HasVendorID() {
					t.Error("Expected vendor flag to be set")
				}
				if msg.ExchangeHeader.VendorID != 0x1234 {
					t.Errorf("Expected vendorID 0x1234, got 0x%04X", msg.ExchangeHeader.VendorID)
				}
				if msg.ExchangeHeader.ProtocolID != 0xfff1 {
					t.Errorf("Expected protocolID 0xfff1, got 0x%04X", msg.ExchangeHeader.ProtocolID)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := hex.DecodeString(tt.hexPayload)
			if err != nil {
				t.Fatalf("Failed to decode hex payload: %v", err)
			}

			msg, err := DecodeMessage(data)
			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("DecodeMessage failed: %v", err)
			}

			t.Logf("Decoded message: %s", msg.String())

			if tt.validateFunc != nil {
				tt.validateFunc(t, msg)
			}

			// Verify roundtrip encoding
			encoded := msg.Encode()
			if len(encoded) != len(data) {
				t.Errorf("Encoded length mismatch: got %d, want %d", len(encoded), len(data))
			}
		})
	}
}

// TestDecodeTruncatedPayloads tests error handling for truncated messages.
func TestDecodeTruncatedPayloads(t *testing.T) {
	tests := []struct {
		name        string
		hexPayload  string
		expectError bool
	}{
		{
			name:        "empty payload",
			hexPayload:  "",
			expectError: true,
		},
		{
			name:        "only 4 bytes",
			hexPayload:  "00000000",
			expectError: true,
		},
		{
			name:        "packet header only",
			hexPayload:  "00" + "0000" + "00" + "01000000", // 8 bytes
			expectError: true,
		},
		{
			name: "truncated exchange header",
			hexPayload: "00" + "0000" + "00" + "01000000" + // Packet header
				"0520", // Only 2 bytes of exchange header
			expectError: true,
		},
		{
			name: "truncated vendor ID",
			hexPayload: "00" + "0000" + "00" + "01000000" + // Packet header
				"11" + "20" + "3412" + "0000" + "12", // Vendor flag set but only 1 byte of vendor ID
			expectError: true,
		},
		{
			name: "truncated ack counter",
			hexPayload: "00" + "0000" + "00" + "01000000" + // Packet header
				"02" + "00" + "3412" + "0000" + "2a00", // ACK flag set but only 2 bytes of ack counter
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := hex.DecodeString(tt.hexPayload)
			if err != nil {
				t.Fatalf("Failed to decode hex payload: %v", err)
			}

			msg, err := DecodeMessage(data)
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for truncated payload, but got valid message: %v", msg)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}
