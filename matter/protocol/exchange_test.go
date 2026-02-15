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

func TestExchangeHeaderTooShort(t *testing.T) {
	shortData := []byte{0x00, 0x00, 0x00} // Only 3 bytes
	_, _, err := DecodeExchangeHeader(shortData)
	if err == nil {
		t.Error("Expected error for short exchange header, got nil")
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
