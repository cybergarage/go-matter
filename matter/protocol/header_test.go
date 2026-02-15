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
	"testing"
)

func TestHeaderTooShort(t *testing.T) {
	shortData := []byte{0x00, 0x00, 0x00} // Only 3 bytes
	_, _, err := DecodeExchangeHeader(shortData)
	if err == nil {
		t.Error("Expected error for short exchange header, got nil")
	}
}

func TestHeaderEncodeDecodeRoundtrip(t *testing.T) {
	tests := []struct {
		name   string
		header Header
	}{
		{
			name: "minimal exchange header",
			header: NewHeader(
				WithHeaderExchangeFlags(0x01), // Initiator
				WithHeaderOpcode(0x20),
				WithHeaderExchangeID(0x1234),
				WithHeaderProtocolID(0x0000),
			),
		},
		{
			name: "exchange header with reliability flag",
			header: NewHeader(
				WithHeaderExchangeFlags(0x05), // Initiator | Reliability
				WithHeaderOpcode(0x30),
				WithHeaderExchangeID(0xABCD),
				WithHeaderProtocolID(0x0001),
			),
		},
		{
			name: "exchange header with ACK",
			header: NewHeader(
				WithHeaderExchangeFlags(0x02), // Ack flag
				WithHeaderOpcode(0x10),
				WithHeaderExchangeID(0x5678),
				WithHeaderProtocolID(0x0000),
				WithHeaderAckCounter(0x11223344),
			),
		},
		{
			name: "exchange header with vendor ID",
			header: NewHeader(
				WithHeaderExchangeFlags(0x11), // Initiator | Vendor
				WithHeaderOpcode(0x40),
				WithHeaderExchangeID(0x9999),
				WithHeaderProtocolID(0xFFF1),
				WithHeaderVendorID(0x1234),
			),
		},
		{
			name: "exchange header with all flags",
			header: NewHeader(
				WithHeaderExchangeFlags(0x1F), // All flags set
				WithHeaderOpcode(0x50),
				WithHeaderExchangeID(0xEEEE),
				WithHeaderProtocolID(0x0002),
				WithHeaderVendorID(0xABCD),
				WithHeaderAckCounter(0xDEADBEEF),
			),
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
			if decoded.ExchangeFlags() != tt.header.ExchangeFlags() {
				t.Errorf("ExchangeFlags mismatch: got 0x%02X, want 0x%02X", decoded.ExchangeFlags(), tt.header.ExchangeFlags())
			}
			if decoded.Opcode() != tt.header.Opcode() {
				t.Errorf("Opcode mismatch: got 0x%02X, want 0x%02X", decoded.Opcode(), tt.header.Opcode())
			}
			if decoded.ExchangeID() != tt.header.ExchangeID() {
				t.Errorf("ExchangeID mismatch: got 0x%04X, want 0x%04X", decoded.ExchangeID(), tt.header.ExchangeID())
			}
			if decoded.ProtocolID() != tt.header.ProtocolID() {
				t.Errorf("ProtocolID mismatch: got 0x%04X, want 0x%04X", decoded.ProtocolID(), tt.header.ProtocolID())
			}
			if tt.header.HasVendorID() && decoded.VendorID() != tt.header.VendorID() {
				t.Errorf("VendorID mismatch: got 0x%04X, want 0x%04X", decoded.VendorID(), tt.header.VendorID())
			}
			if tt.header.IsAck() && decoded.AckCounter() != tt.header.AckCounter() {
				t.Errorf("AckCounter mismatch: got 0x%08X, want 0x%08X", decoded.AckCounter(), tt.header.AckCounter())
			}
		})
	}
}
