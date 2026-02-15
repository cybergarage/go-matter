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
	"fmt"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter/io"
	"github.com/cybergarage/go-matter/matter/protocol"
	"github.com/cybergarage/go-matter/matter/protocol/mrp"
)

// Codec wraps a raw Transport and provides Matter message framing and MRP ACK handling.
// It automatically decodes incoming messages and sends standalone ACKs when requested.
type Codec struct {
	transport      io.Transport
	messageCounter *mrp.MessageCounter
	autoAck        bool
}

// NewCodec creates a new Codec that wraps the given transport.
// autoAck enables automatic sending of standalone ACKs when reliability is requested.
func NewCodec(t io.Transport, autoAck bool) *Codec {
	return &Codec{
		transport:      t,
		messageCounter: mrp.NewMessageCounter(),
		autoAck:        autoAck,
	}
}

// Transmit encodes a Matter message and sends it over the transport.
func (c *Codec) Transmit(ctx context.Context, msg protocol.Message) error {
	encoded := msg.Bytes()
	log.Debugf("Transmit Matter message: %s", msg.String())
	return c.transport.Transmit(ctx, encoded)
}

// TransmitBytes sends raw bytes directly over the transport (for backward compatibility).
func (c *Codec) TransmitBytes(ctx context.Context, b []byte) error {
	return c.transport.Transmit(ctx, b)
}

// Receive reads a message from the transport, decodes it, and optionally sends an ACK.
// Returns the decoded message or an error.
func (c *Codec) Receive(ctx context.Context) (protocol.Message, error) {
	// Read raw bytes from transport
	data, err := c.transport.Receive(ctx)
	if err != nil {
		return nil, fmt.Errorf("transport receive failed: %w", err)
	}

	// Decode the message
	msg, err := protocol.DecodeMessage(data)
	if err != nil {
		log.Warnf("Failed to decode Matter message (%d bytes): %v", len(data), err)
		log.HexWarn(data)
		return nil, fmt.Errorf("message decode failed: %w", err)
	}

	log.Debugf("Received Matter message: %s", msg.String())

	// Check if ACK is requested
	if c.autoAck && mrp.IsAckRequested(msg) {
		log.Debugf("ACK requested for message counter %d", msg.MessageCounter())

		// Build and send standalone ACK
		ack := mrp.BuildStandaloneAck(msg, c.messageCounter.Next())
		ackBytes := ack.Bytes()

		log.Debugf("Sending standalone ACK: %s", ack.String())

		if err := c.transport.Transmit(ctx, ackBytes); err != nil {
			log.Warnf("Failed to send standalone ACK: %v", err)
			// Don't return error - the message was received successfully
		}
	}

	return msg, nil
}

// ReceiveBytes reads raw bytes from the transport without decoding (for backward compatibility).
func (c *Codec) ReceiveBytes(ctx context.Context) ([]byte, error) {
	return c.transport.Receive(ctx)
}

// NextMessageCounter returns the next message counter value for outbound messages.
func (c *Codec) NextMessageCounter() uint32 {
	return c.messageCounter.Next()
}

// SetAutoAck enables or disables automatic ACK sending.
func (c *Codec) SetAutoAck(enabled bool) {
	c.autoAck = enabled
}
