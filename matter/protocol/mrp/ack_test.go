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

	"github.com/cybergarage/go-matter/matter/encoding/message"
)

func TestBuildStandaloneAck(t *testing.T) {
	// Create a message that requests acknowledgement
	receivedMsg := message.NewMessage(
		message.WithMessageFrameHeader(
			message.NewHeader(
				message.WithHeaderFlags(0x00),
				message.WithHeaderSessionID(0x1234),
				message.WithHeaderSecurityFlags(0x00),
				message.WithHeaderMessageCounter(42),
			)),
		message.WithMessageProtocolHeader(
			message.NewProtocolHeader(
				message.WithHeaderExchangeFlags(message.ExchangeFlagInitiator|message.ExchangeFlagReliability),
				message.WithHeaderOpcode(0x20),
				message.WithHeaderExchangeID(0x5678),
				message.WithHeaderProtocolID(0x0000),
			),
		),
		message.WithMessagePayload([]byte{0x01, 0x02, 0x03}),
	)

	outboundCounter := MessageCounter(100)
	ackMsg := BuildStandaloneAck(receivedMsg, outboundCounter)

	// Verify ACK packet header
	if ackMsg.SessionID() != receivedMsg.SessionID() {
		t.Errorf("ACK SessionID mismatch: got 0x%04X, want 0x%04X", ackMsg.SessionID(), receivedMsg.SessionID())
	}
	if ackMsg.MessageCounter() != outboundCounter {
		t.Errorf("ACK MessageCounter mismatch: got %d, want %d", ackMsg.MessageCounter(), outboundCounter)
	}

	// Verify ACK exchange header
	if !ackMsg.IsAcknowledgement() {
		t.Error("Expected ACK flag to be set")
	}
	if ackMsg.IsReliability() {
		t.Error("ACK should not have reliability flag set")
	}
	if ackMsg.ExchangeID() != receivedMsg.ExchangeID() {
		t.Errorf("ACK ExchangeID mismatch: got 0x%04X, want 0x%04X", ackMsg.ExchangeID(), receivedMsg.ExchangeID())
	}
	ackCounter, hasAckCounter := ackMsg.AckCounter()
	receivedMsgCounter := receivedMsg.MessageCounter()
	if !hasAckCounter {
		t.Error("Expected AckCounter to be present")
	} else if ackCounter != receivedMsgCounter {
		t.Errorf("ACK AckCounter mismatch: got %d, want %d", ackCounter, receivedMsgCounter)
	}

	// Verify ACK has no payload
	if len(ackMsg.Payload()) != 0 {
		t.Errorf("Expected empty payload for standalone ACK, got %d bytes", len(ackMsg.Payload()))
	}
}

func TestBuildStandaloneAckWithSourceNode(t *testing.T) {
	// Create a message with source node ID
	receivedMsg := message.NewMessage(
		message.WithMessageFrameHeader(
			message.NewHeader(
				message.WithHeaderSessionID(0x1234),
				message.WithHeaderSecurityFlags(0x00),
				message.WithHeaderMessageCounter(42),
				message.WithHeaderSourceNodeID(0xAABBCCDDEEFF0011),
			),
		),
		message.WithMessageProtocolHeader(
			message.NewProtocolHeader(
				message.WithHeaderExchangeFlags(message.ExchangeFlagInitiator|message.ExchangeFlagReliability),
				message.WithHeaderOpcode(0x20),
				message.WithHeaderExchangeID(0x5678),
				message.WithHeaderProtocolID(0x0000),
			)),
		message.WithMessagePayload([]byte{0x01, 0x02, 0x03}),
	)

	outboundCounter := MessageCounter(100)
	ackMsg := BuildStandaloneAck(receivedMsg, outboundCounter)

	// Verify that the ACK has the destination node ID set to the source of the received message
	destNodeID, hasDestNodeID := ackMsg.DestinationNodeID()
	if !hasDestNodeID {
		t.Error("Expected ACK to have destination node ID set")
	}
	sourceNodeID, hasSourceNodeID := receivedMsg.SourceNodeID()
	if !hasSourceNodeID {
		t.Error("Received message should have source node ID set")
	}
	if destNodeID != sourceNodeID {
		t.Errorf("ACK DestNodeID mismatch: got 0x%016X, want 0x%016X", destNodeID, sourceNodeID)
	}
}

func TestIsAckRequested(t *testing.T) {
	tests := []struct {
		name     string
		msg      message.Message
		expected bool
	}{
		{
			name: "message with reliability flag",
			msg: message.NewMessage(
				message.WithMessageFrameHeader(
					message.NewHeader(),
				),
				message.WithMessageProtocolHeader(
					message.NewProtocolHeader(
						message.WithHeaderExchangeFlags(message.ExchangeFlagReliability),
					),
				),
				message.WithMessagePayload(nil),
			),
			expected: true,
		},
		{
			name: "message without reliability flag",
			msg: message.NewMessage(
				message.WithMessageFrameHeader(
					message.NewHeader(),
				),
				message.WithMessageProtocolHeader(
					message.NewProtocolHeader(
						message.WithHeaderExchangeFlags(message.ExchangeFlagInitiator),
					),
				),
				message.WithMessagePayload(nil),
			),
			expected: false,
		},
		{
			name: "message with multiple flags including reliability",
			msg: message.NewMessage(
				message.WithMessageFrameHeader(
					message.NewHeader(),
				),
				message.WithMessageProtocolHeader(
					message.NewProtocolHeader(
						message.WithHeaderExchangeFlags(message.ExchangeFlagInitiator|message.ExchangeFlagReliability),
					),
				),
				message.WithMessagePayload(nil),
			),
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

func TestAckEncodeDecodeRoundtrip(t *testing.T) {
	// Create a message that requests acknowledgement
	receivedMsg := message.NewMessage(
		message.WithMessageFrameHeader(
			message.NewHeader(
				message.WithHeaderFlags(0x00),
				message.WithHeaderSessionID(0x1234),
				message.WithHeaderSecurityFlags(0x00),
				message.WithHeaderMessageCounter(42),
			)),
		message.WithMessageProtocolHeader(
			message.NewProtocolHeader(
				message.WithHeaderExchangeFlags(message.ExchangeFlagInitiator|message.ExchangeFlagReliability),
				message.WithHeaderOpcode(0x20),
				message.WithHeaderExchangeID(0x5678),
				message.WithHeaderProtocolID(0x0000),
			)),
		message.WithMessagePayload([]byte{0x01, 0x02, 0x03}),
	)

	outboundCounter := MessageCounter(100)
	ackMsg := BuildStandaloneAck(receivedMsg, outboundCounter)

	// Encode ACK
	encoded := ackMsg.Bytes()

	// Decode ACK
	decoded, err := message.NewMessageFromBytes(encoded)
	if err != nil {
		t.Fatalf("Failed to decode ACK: %v", err)
	}

	// Verify decoded ACK matches original
	if !decoded.IsAcknowledgement() {
		t.Error("Decoded message should have ACK flag set")
	}
	ackCounter, hasAckCounter := decoded.AckCounter()
	receivedMsgCounter := receivedMsg.MessageCounter()
	if !hasAckCounter {
		t.Error("Expected AckCounter to be present")
	} else if ackCounter != receivedMsgCounter {
		t.Errorf("Decoded AckCounter mismatch: got %d, want %d", ackCounter, receivedMsgCounter)
	}
}
