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

	"github.com/cybergarage/go-matter/matter/encoding/message"
)

func TestMessageEncodeDecodeRoundtrip(t *testing.T) {
	tests := []struct {
		name    string
		message *Message
	}{
		{
			name: "simple message with payload",
			message: &Message{
				Header: message.NewHeader(
					message.WithHeaderFlags(0x00),
					message.WithHeaderSessionID(0x0000),
					message.WithHeaderSecurityFlags(0x00),
					message.WithHeaderMessageCounter(1),
				),
				ExchangeHeader: &Header{
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
				Header: message.NewHeader(
					message.WithHeaderFlags(0x00),
					message.WithHeaderSessionID(0x0000),
					message.WithHeaderSecurityFlags(0x00),
					message.WithHeaderMessageCounter(2),
				),
				ExchangeHeader: &Header{
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
			if decoded.MessageCounter() != tt.message.MessageCounter() {
				t.Errorf("MessageCounter mismatch: got %d, want %d", decoded.MessageCounter(), tt.message.MessageCounter())
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
	if msg.MessageCounter() != 1 {
		t.Errorf("MessageCounter mismatch: got %d, want 1", msg.MessageCounter())
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
