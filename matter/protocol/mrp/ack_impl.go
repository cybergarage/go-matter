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
	"bytes"
	"fmt"
	"io"

	"github.com/cybergarage/go-matter/matter/encoding/json"
	"github.com/cybergarage/go-matter/matter/encoding/message"
)

// AckOption defines a functional option for configuring the Ack.
type AckOption func(*ack)

// WithAckReferenceMessage sets the reference message for the ACK, which is used to extract relevant fields for the ACK response.
func WithAckReferenceMessage(msg message.Message) AckOption {
	return func(a *ack) {
		a.refMsg = msg
	}
}

// WithAckMessageCounter sets the message counter to be used in the ACK message. This is typically the next counter value for outgoing messages.
func WithAckMessageCounter(counter MessageCounter) AckOption {
	return func(a *ack) {
		a.outCounter = counter
	}
}

type ack struct {
	refMsg     message.Message
	outCounter MessageCounter
	msg        message.Message
}

func newAck(opts ...AckOption) *ack {
	a := &ack{
		refMsg:     nil,
		outCounter: 0,
		msg:        nil,
	}
	for _, opt := range opts {
		opt(a)
	}
	if a.refMsg != nil {
		a.msg = newAckMessageWith(a.refMsg, a.outCounter)
	}
	return a
}

// NewAck creates a new ACK message based on the provided options.
func NewAck(opts ...AckOption) (Ack, error) {
	a := newAck(opts...)
	if a.msg == nil {
		return nil, fmt.Errorf("failed to create ACK message")
	}
	return a, nil
}

// NewAckFromMessage creates an ACK message from an existing message, extracting relevant fields.
func NewAckFromMessage(msg message.Message) Ack {
	return newAck(func(a *ack) {
		a.msg = msg
	})
}

// NewAckFromReader creates an ACK message by reading and parsing a message from the provided reader.
func NewAckFromReader(r io.Reader) (Ack, error) {
	msg, err := message.NewMessageFromReader(r)
	if err != nil {
		return nil, err
	}
	return NewAckFromMessage(msg), nil
}

// NewAckFromBytes creates an ACK message by parsing a byte slice into a message.
func NewAckFromBytes(b []byte) (Ack, error) {
	return NewAckFromReader(bytes.NewReader(b))
}

func (a *ack) Message() message.Message {
	return a.msg
}

func (a *ack) IsReliability() bool {
	if a.msg == nil {
		return false
	}
	return a.msg.IsReliability()
}

func (a *ack) IsAcknowledgement() bool {
	if a.msg == nil {
		return false
	}
	return a.msg.IsAcknowledgement()
}

func (a *ack) MessageCounter() MessageCounter {
	if a.msg == nil {
		return MessageCounter(0)
	}
	return a.msg.MessageCounter()
}

func (a *ack) Bytes() []byte {
	if a.msg == nil {
		return []byte{}
	}
	return a.msg.Bytes()
}

func (a *ack) Map() map[string]any {
	m := map[string]any{}
	if a.msg != nil {
		m["reliability"] = a.IsReliability()
		m["acknowledgement"] = a.IsAcknowledgement()
		m["messageCounter"] = a.MessageCounter()
	}
	return m
}

func (a *ack) String() string {
	return json.MustMarshal(a.Map())
}

func newAckMessageWith(receivedMsg message.Message, outboundCounter MessageCounter) message.Message {
	// Build message header for ACK: preserve version/control and security context
	msgHeaderOpts := []message.HeaderOption{
		message.WithHeaderFlags(receivedMsg.Flags()),
		message.WithHeaderSessionID(receivedMsg.SessionID()),
		message.WithHeaderSecurityFlags(receivedMsg.SecurityFlags()),
		message.WithHeaderMessageCounter(outboundCounter),
	}

	// If received message had source node, send it back as destination
	msgSrcNodeID, msgHasSrcNodeID := receivedMsg.SourceNodeID()
	if msgHasSrcNodeID {
		msgHeaderOpts = append(msgHeaderOpts, message.WithHeaderDestinationNodeID(msgSrcNodeID))
	}

	msgHeader := message.NewHeader(msgHeaderOpts...)

	// Build exchange header for ACK
	// Reference: Matter Core Spec 1.5, Section 4.11.8
	// An ACK message has:
	// - A flag set (bit 1)
	// - No R flag (reliability not requested for ACK itself)
	// - Opcode can be 0x00 (no protocol operation, just ACK)
	// - AckCounter field references the message being acknowledged
	exchangeHeader := message.NewProtocolHeader(
		message.WithHeaderExchangeFlags(message.AckFlag), // A flag only
		message.WithHeaderOpcode(0x00),                   // Standalone ACK has no opcode
		message.WithHeaderExchangeID(receivedMsg.ExchangeID()),
		message.WithHeaderProtocolID(receivedMsg.ProtocolID()),
		message.WithHeaderAckCounter(receivedMsg.MessageCounter()),
	)

	// Standalone ACK has no payload
	return message.NewMessage(
		message.WithMessageFrameHeader(msgHeader),
		message.WithMessageProtocolHeader(exchangeHeader),
		message.WithMessagePayload([]byte{}),
	)
}
