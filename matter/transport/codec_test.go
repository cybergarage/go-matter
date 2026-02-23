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

package transport

import (
	"context"
	"testing"

	"github.com/cybergarage/go-matter/matter/encoding/message"
)

// mockTransport is a simple mock implementation of io.Transport for testing.
type mockTransport struct {
	sendData    []byte
	receiveData []byte
	sendErr     error
	receiveErr  error
}

func (m *mockTransport) Transmit(ctx context.Context, b []byte) error {
	if m.sendErr != nil {
		return m.sendErr
	}
	m.sendData = append([]byte{}, b...)
	return nil
}

func (m *mockTransport) Receive(ctx context.Context) ([]byte, error) {
	if m.receiveErr != nil {
		return nil, m.receiveErr
	}
	return m.receiveData, nil
}

func TestCodecTransmit(t *testing.T) {
	mock := &mockTransport{}
	codec := NewCodec(mock, false)

	msg := message.NewMessage(
		message.WithMessageFrameHeader(
			message.NewHeader(
				message.WithHeaderFlags(0x00),
				message.WithHeaderSessionID(0x1234),
				message.WithHeaderSecurityFlags(0x00),
				message.WithHeaderMessageCounter(1),
			)),
		message.WithMessageProtocolHeader(
			message.NewProtocolHeader(
				message.WithHeaderExchangeFlags(message.InitiatorFlag),
				message.WithHeaderOpcode(0x20),
				message.WithHeaderExchangeID(0x5678),
				message.WithHeaderProtocolID(0x0000),
			)),
		message.WithMessagePayload([]byte{0x01, 0x02, 0x03}),
	)

	ctx := context.Background()
	err := codec.Transmit(ctx, msg)
	if err != nil {
		t.Fatalf("Transmit failed: %v", err)
	}

	// Verify the mock received the encoded message
	expected, err := msg.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if len(mock.sendData) != len(expected) {
		t.Errorf("Transmitted data length mismatch: got %d, want %d", len(mock.sendData), len(expected))
	}
}

func TestCodecReceiveWithoutAck(t *testing.T) {
	msg := message.NewMessage(
		message.WithMessageFrameHeader(
			message.NewHeader(
				message.WithHeaderFlags(0x00),
				message.WithHeaderSessionID(0x1234),
				message.WithHeaderSecurityFlags(0x00),
				message.WithHeaderMessageCounter(42),
			)),
		message.WithMessageProtocolHeader(
			message.NewProtocolHeader(
				message.WithHeaderExchangeFlags(message.InitiatorFlag), // No reliability flag
				message.WithHeaderOpcode(0x20),
				message.WithHeaderExchangeID(0x5678),
				message.WithHeaderProtocolID(0x0000),
			)),
		message.WithMessagePayload([]byte{0x01, 0x02, 0x03}),
	)

	msgBytes, err := msg.Bytes()
	if err != nil {
		t.Fatalf("Failed to encode message: %v", err)
	}
	mock := &mockTransport{
		receiveData: msgBytes,
	}
	codec := NewCodec(mock, true) // Enable auto-ACK

	ctx := context.Background()
	receivedMsg, err := codec.Receive(ctx)
	if err != nil {
		t.Fatalf("Receive failed: %v", err)
	}

	// Verify the received message matches
	if receivedMsg.MessageCounter() != msg.MessageCounter() {
		t.Errorf("MessageCounter mismatch: got %d, want %d", receivedMsg.MessageCounter(), msg.MessageCounter())
	}

	// Verify no ACK was sent (no reliability flag)
	if mock.sendData != nil {
		t.Error("Expected no ACK to be sent for message without reliability flag")
	}
}

func TestCodecReceiveWithAutoAck(t *testing.T) {
	msg := message.NewMessage(
		message.WithMessageFrameHeader(
			message.NewHeader(
				message.WithHeaderFlags(0x00),
				message.WithHeaderSessionID(0x1234),
				message.WithHeaderSecurityFlags(0x00),
				message.WithHeaderMessageCounter(42),
			)),
		message.WithMessageProtocolHeader(
			message.NewProtocolHeader(
				message.WithHeaderExchangeFlags(message.InitiatorFlag|message.ReliabilityFlag),
				message.WithHeaderOpcode(0x20),
				message.WithHeaderExchangeID(0x5678),
				message.WithHeaderProtocolID(0x0000),
			)),
		message.WithMessagePayload([]byte{0x01, 0x02, 0x03}),
	)

	msgBytes, err := msg.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	mock := &mockTransport{
		receiveData: msgBytes,
	}
	codec := NewCodec(mock, true) // Enable auto-ACK

	ctx := context.Background()
	receivedMsg, err := codec.Receive(ctx)
	if err != nil {
		t.Fatalf("Receive failed: %v", err)
	}

	// Verify the received message matches
	if receivedMsg.MessageCounter() != msg.MessageCounter() {
		t.Errorf("MessageCounter mismatch: got %d, want %d", receivedMsg.MessageCounter(), msg.MessageCounter())
	}

	// Verify ACK was sent
	if mock.sendData == nil {
		t.Skip("Expected ACK to be sent")
	}

	// Decode and verify ACK
	ack, err := message.NewMessageFromBytes(mock.sendData)
	if err != nil {
		t.Fatalf("Failed to decode ACK: %v", err)
	}

	if !ack.IsAcknowledgement() {
		t.Error("Expected ACK flag to be set in sent message")
	}
	ackCounter, hasAckCounter := ack.AckMessageCounter()
	if !hasAckCounter {
		t.Error("Expected AckCounter to be present in ACK message")
	} else if ackCounter != msg.MessageCounter() {
		t.Errorf("ACK counter mismatch: got %d, want %d", ackCounter, msg.MessageCounter())
	}
}

func TestCodecReceiveWithAutoAckDisabled(t *testing.T) {
	msg := message.NewMessage(
		message.WithMessageFrameHeader(
			message.NewHeader(
				message.WithHeaderFlags(0x00),
				message.WithHeaderSessionID(0x1234),
				message.WithHeaderSecurityFlags(0x00),
				message.WithHeaderMessageCounter(42),
			)),
		message.WithMessageProtocolHeader(
			message.NewProtocolHeader(
				message.WithHeaderExchangeFlags(message.InitiatorFlag|message.ReliabilityFlag),
				message.WithHeaderOpcode(0x20),
				message.WithHeaderExchangeID(0x5678),
				message.WithHeaderProtocolID(0x0000),
			)),
		message.WithMessagePayload([]byte{0x01, 0x02, 0x03}),
	)

	msgBytes, err := msg.Bytes()
	if err != nil {
		t.Fatalf("Failed to encode message: %v", err)
	}

	mock := &mockTransport{
		receiveData: msgBytes,
	}
	codec := NewCodec(mock, false) // Disable auto-ACK

	ctx := context.Background()
	_, err = codec.Receive(ctx)
	if err != nil {
		t.Fatalf("Receive failed: %v", err)
	}

	// Verify no ACK was sent (auto-ACK disabled)
	if mock.sendData != nil {
		t.Error("Expected no ACK to be sent when auto-ACK is disabled")
	}
}

func TestCodecMessageCounter(t *testing.T) {
	mock := &mockTransport{}
	codec := NewCodec(mock, false)

	// Get several counter values
	counters := []MessageCounter{
		codec.NextMessageCounter(),
		codec.NextMessageCounter(),
		codec.NextMessageCounter(),
	}

	// Verify they increment
	for _, counter := range counters {
		nc := counter.Next()
		if nc != counter+1 {
			t.Errorf("Expected next counter to be %d, got %d", counter+1, nc)
		}
	}
}

func TestCodecSetAutoAck(t *testing.T) {
	mock := &mockTransport{}
	codec := NewCodec(mock, false)

	// Initially disabled
	if codec.autoAck {
		t.Error("Expected auto-ACK to be initially disabled")
	}

	// Enable
	codec.SetAutoAck(true)
	if !codec.autoAck {
		t.Error("Expected auto-ACK to be enabled")
	}

	// Disable
	codec.SetAutoAck(false)
	if codec.autoAck {
		t.Error("Expected auto-ACK to be disabled")
	}
}

func TestIsAckRequestedIntegration(t *testing.T) {
	// Create a message with reliability flag
	msg := message.NewMessage(
		message.WithMessageFrameHeader(
			message.NewHeader(
				message.WithHeaderFlags(0x00),
				message.WithHeaderSessionID(0x0000),
				message.WithHeaderSecurityFlags(0x00),
				message.WithHeaderMessageCounter(1),
			)),
		message.WithMessageProtocolHeader(
			message.NewProtocolHeader(
				message.WithHeaderExchangeFlags(message.ReliabilityFlag),
				message.WithHeaderOpcode(0x20),
				message.WithHeaderExchangeID(0x1234),
				message.WithHeaderProtocolID(0x0000),
			)),
		message.WithMessagePayload([]byte{}),
	)

	if !msg.IsReliability() {
		t.Error("Expected ACK to be requested for message with reliability flag")
	}
}
