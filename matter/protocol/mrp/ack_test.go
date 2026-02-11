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

package mrp

import (
	"testing"

	"github.com/cybergarage/go-matter/matter/protocol/mattermsg"
)

func TestBuildStandaloneAck(t *testing.T) {
	// Create a message that requests acknowledgement
	receivedMsg := &mattermsg.Message{
		PacketHeader: &mattermsg.PacketHeader{
			Flags:          0x00,
			SessionID:      0x1234,
			SecurityFlags:  0x00,
			MessageCounter: 42,
		},
		ExchangeHeader: &mattermsg.ExchangeHeader{
			ExchangeFlags: mattermsg.ExchangeFlagInitiator | mattermsg.ExchangeFlagReliability,
			Opcode:        0x20,
			ExchangeID:    0x5678,
			ProtocolID:    0x0000,
		},
		Payload: []byte{0x01, 0x02, 0x03},
	}

	outboundCounter := uint32(100)
	ackMsg := BuildStandaloneAck(receivedMsg, outboundCounter)

	// Verify ACK packet header
	if ackMsg.PacketHeader.SessionID != receivedMsg.PacketHeader.SessionID {
		t.Errorf("ACK SessionID mismatch: got 0x%04X, want 0x%04X", ackMsg.PacketHeader.SessionID, receivedMsg.PacketHeader.SessionID)
	}
	if ackMsg.PacketHeader.MessageCounter != outboundCounter {
		t.Errorf("ACK MessageCounter mismatch: got %d, want %d", ackMsg.PacketHeader.MessageCounter, outboundCounter)
	}

	// Verify ACK exchange header
	if !ackMsg.ExchangeHeader.IsAck() {
		t.Error("Expected ACK flag to be set")
	}
	if ackMsg.ExchangeHeader.IsReliabilityRequested() {
		t.Error("ACK should not have reliability flag set")
	}
	if ackMsg.ExchangeHeader.ExchangeID != receivedMsg.ExchangeHeader.ExchangeID {
		t.Errorf("ACK ExchangeID mismatch: got 0x%04X, want 0x%04X", ackMsg.ExchangeHeader.ExchangeID, receivedMsg.ExchangeHeader.ExchangeID)
	}
	if ackMsg.ExchangeHeader.AckCounter != receivedMsg.PacketHeader.MessageCounter {
		t.Errorf("ACK AckCounter mismatch: got %d, want %d", ackMsg.ExchangeHeader.AckCounter, receivedMsg.PacketHeader.MessageCounter)
	}

	// Verify ACK has no payload
	if len(ackMsg.Payload) != 0 {
		t.Errorf("Expected empty payload for standalone ACK, got %d bytes", len(ackMsg.Payload))
	}
}

func TestBuildStandaloneAckWithSourceNode(t *testing.T) {
	// Create a message with source node ID
	receivedMsg := &mattermsg.Message{
		PacketHeader: &mattermsg.PacketHeader{
			Flags:          mattermsg.FlagSourceNodeIDPresent,
			SessionID:      0x1234,
			SecurityFlags:  0x00,
			MessageCounter: 42,
			SourceNodeID:   0xAABBCCDDEEFF0011,
		},
		ExchangeHeader: &mattermsg.ExchangeHeader{
			ExchangeFlags: mattermsg.ExchangeFlagInitiator | mattermsg.ExchangeFlagReliability,
			Opcode:        0x20,
			ExchangeID:    0x5678,
			ProtocolID:    0x0000,
		},
		Payload: []byte{0x01, 0x02, 0x03},
	}

	outboundCounter := uint32(100)
	ackMsg := BuildStandaloneAck(receivedMsg, outboundCounter)

	// Verify that the ACK has the destination node ID set to the source of the received message
	if !ackMsg.PacketHeader.HasDestNodeID() {
		t.Error("Expected ACK to have destination node ID set")
	}
	if ackMsg.PacketHeader.DestNodeID != receivedMsg.PacketHeader.SourceNodeID {
		t.Errorf("ACK DestNodeID mismatch: got 0x%016X, want 0x%016X", ackMsg.PacketHeader.DestNodeID, receivedMsg.PacketHeader.SourceNodeID)
	}
}

func TestIsAckRequested(t *testing.T) {
	tests := []struct {
		name     string
		msg      *mattermsg.Message
		expected bool
	}{
		{
			name: "message with reliability flag",
			msg: &mattermsg.Message{
				PacketHeader: &mattermsg.PacketHeader{},
				ExchangeHeader: &mattermsg.ExchangeHeader{
					ExchangeFlags: mattermsg.ExchangeFlagReliability,
				},
			},
			expected: true,
		},
		{
			name: "message without reliability flag",
			msg: &mattermsg.Message{
				PacketHeader: &mattermsg.PacketHeader{},
				ExchangeHeader: &mattermsg.ExchangeHeader{
					ExchangeFlags: mattermsg.ExchangeFlagInitiator,
				},
			},
			expected: false,
		},
		{
			name: "message with multiple flags including reliability",
			msg: &mattermsg.Message{
				PacketHeader: &mattermsg.PacketHeader{},
				ExchangeHeader: &mattermsg.ExchangeHeader{
					ExchangeFlags: mattermsg.ExchangeFlagInitiator | mattermsg.ExchangeFlagReliability,
				},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsAckRequested(tt.msg)
			if result != tt.expected {
				t.Errorf("IsAckRequested() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestMessageCounter(t *testing.T) {
	counter := NewMessageCounter()

	// Test initial value
	if counter.Current() != 0 {
		t.Errorf("Initial counter value should be 0, got %d", counter.Current())
	}

	// Test Next() increments
	for i := uint32(0); i < 10; i++ {
		val := counter.Next()
		if val != i {
			t.Errorf("Expected counter value %d, got %d", i, val)
		}
	}

	// Test current value after incrementing
	if counter.Current() != 10 {
		t.Errorf("Expected current counter value 10, got %d", counter.Current())
	}
}

func TestAckEncodeDecodeRoundtrip(t *testing.T) {
	// Create a message that requests acknowledgement
	receivedMsg := &mattermsg.Message{
		PacketHeader: &mattermsg.PacketHeader{
			Flags:          0x00,
			SessionID:      0x1234,
			SecurityFlags:  0x00,
			MessageCounter: 42,
		},
		ExchangeHeader: &mattermsg.ExchangeHeader{
			ExchangeFlags: mattermsg.ExchangeFlagInitiator | mattermsg.ExchangeFlagReliability,
			Opcode:        0x20,
			ExchangeID:    0x5678,
			ProtocolID:    0x0000,
		},
		Payload: []byte{0x01, 0x02, 0x03},
	}

	// Build ACK
	ackMsg := BuildStandaloneAck(receivedMsg, 100)

	// Encode ACK
	encoded := ackMsg.Encode()

	// Decode ACK
	decoded, err := mattermsg.DecodeMessage(encoded)
	if err != nil {
		t.Fatalf("Failed to decode ACK: %v", err)
	}

	// Verify decoded ACK matches original
	if !decoded.ExchangeHeader.IsAck() {
		t.Error("Decoded message should have ACK flag set")
	}
	if decoded.ExchangeHeader.AckCounter != receivedMsg.PacketHeader.MessageCounter {
		t.Errorf("Decoded AckCounter mismatch: got %d, want %d", decoded.ExchangeHeader.AckCounter, receivedMsg.PacketHeader.MessageCounter)
	}
}
