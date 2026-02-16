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
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/cybergarage/go-matter/matter/encoding/message"
)

const (
	minHeaderSize        = 6
	extPayloadLengthSize = 2
)

type frameHeader = message.Header
type protocolHeader = Header

type messageImpl struct {
	frameHeader
	protocolHeader
	extensions []byte
	payload    []byte
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

// WithMessageExtensions sets the message extensions of the Message.
func WithMessageExtensions(ext []byte) MessageOption {
	return func(m *messageImpl) {
		m.extensions = ext
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
		extensions:     []byte{},            // Default empty extensions
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
	// 4.4.1. Message Header Field Descriptions
	msgHeader, msgHeaderSize, err := message.NewHeaderFromBytes(data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode message header: %w", err)
	}

	if len(data) < msgHeaderSize+minHeaderSize {
		return nil, fmt.Errorf("message too short: need at least %d bytes for headers, got %d", msgHeaderSize+minHeaderSize, len(data))
	}

	// 4.4.3. Protocol Header Field Descriptions
	protocolHeader, protocolSize, err := NewHeaderFromBytes(data[msgHeaderSize:])
	if err != nil {
		return nil, fmt.Errorf("failed to decode protocol header: %w", err)
	}

	// 4.4.1.7. Message Extensions (variable)
	extentionsSize := 0
	extentionPayload := []byte{}
	if msgHeader.SecurityFlags().HasMessageExtensions() {
		offset := msgHeaderSize + protocolSize
		if len(data) < offset+extPayloadLengthSize {
			return nil, fmt.Errorf("message too short: expected message extensions length field but only %d bytes remain", len(data)-msgHeaderSize-protocolSize)
		}
		extentionsSize = int(binary.LittleEndian.Uint16(data[offset : offset+extPayloadLengthSize]))
		offset += extPayloadLengthSize
		if len(data) < offset+extentionsSize {
			return nil, fmt.Errorf("message too short: expected %d bytes of message extensions but only %d bytes remain", extentionsSize, len(data)-offset)
		}
		extentionPayload = data[offset+extPayloadLengthSize : offset+extPayloadLengthSize+extentionsSize]
	}

	// 4.4.3.8. Application Payload (variable length)
	headerSize := msgHeaderSize + protocolSize + extentionsSize
	if len(data) < headerSize {
		return nil, fmt.Errorf("message too short: need at least %d bytes for headers and extensions, got %d", headerSize, len(data))
	}
	payload := data[headerSize:]

	return &messageImpl{
		frameHeader:    msgHeader,
		protocolHeader: protocolHeader,
		extensions:     extentionPayload,
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
