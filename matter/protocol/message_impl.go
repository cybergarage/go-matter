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
	"fmt"

	"github.com/cybergarage/go-matter/matter/encoding/message"
)

type frameHeader = message.Header
type protocolHeader = Header

type messageImpl struct {
	frameHeader
	protocolHeader
	payload []byte
}

// MessageOption represents a functional option for configuring a Message.
type MessageOption func(*messageImpl)

// WithMessageFrameHeader sets the message header of the Message.
func WithMessageFrameHeader(header message.Header) MessageOption {
	return func(m *messageImpl) {
		m.frameHeader = header
	}
}

// WithMessageProtocolHeader sets the protocol header of the Message.
func WithMessageProtocolHeader(header Header) MessageOption {
	return func(m *messageImpl) {
		m.protocolHeader = header
	}
}

// WithMessagePayload sets the payload of the Message.
func WithMessagePayload(payload []byte) MessageOption {
	return func(m *messageImpl) {
		m.payload = payload
	}
}

// NewMessage creates a new Message instance with the provided options.
func NewMessage(opts ...MessageOption) Message {
	m := &messageImpl{
		frameHeader:    message.NewHeader(), // Default empty header
		protocolHeader: NewHeader(),         // Default empty header
		payload:        []byte{},            // Default empty payload
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// NewMessageFromBytes parses a complete Matter message from bytes.
// Returns the message or an error.
func NewMessageFromBytes(data []byte) (Message, error) {
	// Decode message header
	msgHeader, msgHeaderSize, err := message.NewHeaderFromBytes(data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode message header: %w", err)
	}

	if len(data) < msgHeaderSize+6 {
		return nil, fmt.Errorf("message too short: need at least %d bytes for headers, got %d", msgHeaderSize+6, len(data))
	}

	// Decode protocol header
	protocolHeader, protocolSize, err := NewHeaderFromBytes(data[msgHeaderSize:])
	if err != nil {
		return nil, fmt.Errorf("failed to decode protocol header: %w", err)
	}

	// Extract payload (everything after headers)
	headerSize := msgHeaderSize + protocolSize
	payload := data[headerSize:]

	return &messageImpl{
		frameHeader:    msgHeader,
		protocolHeader: protocolHeader,
		payload:        payload,
	}, nil
}

// Payload returns the message payload bytes.
func (m *messageImpl) Payload() []byte {
	return m.payload
}

// Bytes serializes the complete message to bytes.
func (m *messageImpl) Bytes() []byte {
	packetBytes := m.frameHeader.Bytes()
	protocolBytes := m.protocolHeader.Bytes()

	result := make([]byte, 0, len(packetBytes)+len(protocolBytes)+len(m.payload))
	result = append(result, packetBytes...)
	result = append(result, protocolBytes...)
	result = append(result, m.payload...)

	return result
}

// String returns a human-readable representation with hex dumps.
func (m *messageImpl) String() string {
	return fmt.Sprintf("Message{\n  %s\n  %s\n  Payload: %d bytes [%s]\n}",
		m.frameHeader.String(),
		m.protocolHeader.String(),
		len(m.payload),
		hex.EncodeToString(m.payload))
}
