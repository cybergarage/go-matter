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
	"sync/atomic"

	"github.com/cybergarage/go-matter/matter/encoding/message"
	"github.com/cybergarage/go-matter/matter/protocol"
)

// BuildStandaloneAck creates a standalone acknowledgement message for a received message.
// The ACK references the message counter of the original message.
// Reference: Matter Core Spec 1.5, Section 4.11.8 (Standalone Acknowledgement).
func BuildStandaloneAck(receivedMsg protocol.Message, outboundCounter uint32) protocol.Message {
	// Build message header for ACK: preserve version/control and security context
	msgHeaderOpts := []message.HeaderOption{
		message.WithHeaderFlags(receivedMsg.Flags()),
		message.WithHeaderSessionID(receivedMsg.SessionID()),
		message.WithHeaderSecurityFlags(receivedMsg.SecurityFlags()),
		message.WithHeaderMessageCounter(outboundCounter),
	}

	// If received message had source node, send it back as destination
	if receivedMsg.HasSourceNodeID() {
		msgHeaderOpts = append(msgHeaderOpts, message.WithHeaderFlags(receivedMsg.Flags()|message.FlagDestNodeIDPresent))
		msgHeaderOpts = append(msgHeaderOpts, message.WithHeaderDestNodeID(receivedMsg.SourceNodeID()))
	}

	msgHeader := message.NewHeader(msgHeaderOpts...)

	// Build exchange header for ACK
	// Reference: Matter Core Spec 1.5, Section 4.11.8
	// An ACK message has:
	// - A flag set (bit 1)
	// - No R flag (reliability not requested for ACK itself)
	// - Opcode can be 0x00 (no protocol operation, just ACK)
	// - AckCounter field references the message being acknowledged
	exchangeHeader := protocol.NewHeader(
		protocol.WithHeaderExchangeFlags(protocol.ExchangeFlagAck), // A flag only
		protocol.WithHeaderOpcode(0x00),                            // Standalone ACK has no opcode
		protocol.WithHeaderExchangeID(receivedMsg.ExchangeID()),
		protocol.WithHeaderProtocolID(receivedMsg.ProtocolID()),
		protocol.WithHeaderAckCounter(receivedMsg.MessageCounter()),
	)

	// Standalone ACK has no payload
	return protocol.NewMessage(
		protocol.WithMessageFrameHeader(msgHeader),
		protocol.WithMessageProtocolHeader(exchangeHeader),
		protocol.WithMessagePayload([]byte{}),
	)
}

// IsAckRequested checks if the received message has the reliability flag set,
// indicating that an acknowledgement is requested.
func IsAckRequested(msg protocol.Message) bool {
	return msg.IsReliabilityRequested()
}

// MessageCounter tracks outbound message counters for a session.
// It is safe for concurrent use by multiple goroutines.
type MessageCounter struct {
	counter uint32
}

// NewMessageCounter creates a new message counter starting from 0.
func NewMessageCounter() *MessageCounter {
	return &MessageCounter{counter: 0}
}

// Next returns the next message counter value and increments the internal counter.
// This method is thread-safe using atomic operations.
func (mc *MessageCounter) Next() uint32 {
	return atomic.AddUint32(&mc.counter, 1) - 1
}

// Current returns the current counter value without incrementing.
// This method is thread-safe using atomic operations.
func (mc *MessageCounter) Current() uint32 {
	return atomic.LoadUint32(&mc.counter)
}
