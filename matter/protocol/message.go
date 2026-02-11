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
)

// Message represents a complete Matter message with packet header, exchange header, and payload.
type Message struct {
	PacketHeader   *PacketHeader
	ExchangeHeader *ExchangeHeader
	Payload        []byte
}

// Encode serializes the complete message to bytes.
func (m *Message) Encode() []byte {
	packetBytes := m.PacketHeader.Encode()
	exchangeBytes := m.ExchangeHeader.Encode()

	result := make([]byte, 0, len(packetBytes)+len(exchangeBytes)+len(m.Payload))
	result = append(result, packetBytes...)
	result = append(result, exchangeBytes...)
	result = append(result, m.Payload...)

	return result
}

// DecodeMessage parses a complete Matter message from bytes.
// Returns the message or an error.
func DecodeMessage(data []byte) (*Message, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("message too short: need at least 8 bytes for packet header, got %d", len(data))
	}

	// Decode packet header
	packetHeader, packetSize, err := DecodePacketHeader(data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode packet header: %w", err)
	}

	if len(data) < packetSize+6 {
		return nil, fmt.Errorf("message too short: need at least %d bytes for headers, got %d", packetSize+6, len(data))
	}

	// Decode exchange header
	exchangeHeader, exchangeSize, err := DecodeExchangeHeader(data[packetSize:])
	if err != nil {
		return nil, fmt.Errorf("failed to decode exchange header: %w", err)
	}

	// Extract payload (everything after headers)
	headerSize := packetSize + exchangeSize
	payload := data[headerSize:]

	return &Message{
		PacketHeader:   packetHeader,
		ExchangeHeader: exchangeHeader,
		Payload:        payload,
	}, nil
}

// String returns a human-readable representation with hex dumps.
func (m *Message) String() string {
	return fmt.Sprintf("Message{\n  %s\n  %s\n  Payload: %d bytes [%s]\n}",
		m.PacketHeader.String(),
		m.ExchangeHeader.String(),
		len(m.Payload),
		hex.EncodeToString(m.Payload))
}
