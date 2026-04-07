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

	"github.com/cybergarage/go-matter/matter/encoding/message"
)

// AckOption defines a functional option for configuring the Ack.
type AckOption func(*ack)

type ack struct {
	headerOpts   []message.HeaderOption
	protocolOpts []message.ProtocolHeaderOption
	message.Message
}

// WithAckReferenceMessage sets the reference message for the ACK, which is used to extract relevant fields for the ACK response.
func WithAckReferenceMessage(refMsg message.Message) AckOption {
	return func(a *ack) {
		a.headerOpts = append(a.headerOpts,
			message.WithHeaderFlags(refMsg.Flags()),
			message.WithHeaderSessionID(refMsg.SessionID()),
			message.WithHeaderSecurityFlags(refMsg.SecurityFlags()),
		)
		refSrcNodeID, hasRefSrcNodeID := refMsg.SourceNodeID()
		if hasRefSrcNodeID {
			a.headerOpts = append(a.headerOpts, message.WithHeaderDestinationNodeID(refSrcNodeID))
		}
		a.protocolOpts = append(a.protocolOpts,
			message.WithHeaderExchangeID(refMsg.ExchangeID()),
			message.WithHeaderProtocolID(refMsg.ProtocolID()),
			message.WithHeaderAckCounter(refMsg.MessageCounter()),
		)
	}
}

// WithAckPrecedingMessage sets the message counter in the ACK based on the preceding message, ensuring that the ACK correctly acknowledges the preceding message and maintains the proper message counter sequence.
func WithAckPrecedingMessage(preMsg message.Message) AckOption {
	return func(a *ack) {
		a.headerOpts = append(a.headerOpts,
			message.WithHeaderMessageCounter(preMsg.MessageCounter().Next()),
		)
	}
}

func withAckMessageCounter(counter message.MessageCounter) AckOption {
	return func(a *ack) {
		a.headerOpts = append(a.headerOpts,
			message.WithHeaderMessageCounter(counter),
		)
	}
}

func newAck(opts ...AckOption) *ack {
	a := &ack{
		headerOpts: []message.HeaderOption{
			message.WithHeaderMessageCounter(NewMessageCounter()),
		},
		// 4.12.7.1. MRP Standalone Acknowledgement
		protocolOpts: []message.ProtocolHeaderOption{
			message.WithHeaderExchangeFlags(message.AckFlag),
			message.WithHeaderProtocolID(message.SecureChannel),
			message.WithHeaderOpcode(message.MRPStandaloneAck),
		},
		Message: nil,
	}
	for _, opt := range opts {
		opt(a)
	}
	if a.Message != nil {
		return a
	}

	// Standalone ACK has no payload
	a.Message = message.NewMessage(
		message.WithMessageFrameHeader(message.NewHeader(a.headerOpts...)),
		message.WithMessageProtocolHeader(message.NewProtocolHeader(a.protocolOpts...)),
		message.WithMessagePayload([]byte{}),
	)

	return a
}

// NewAck creates a new ACK message based on the provided options.
func NewAck(opts ...AckOption) (Ack, error) {
	a := newAck(opts...)
	if a.Message == nil {
		return nil, fmt.Errorf("failed to create ACK message")
	}
	return a, nil
}

// NewAckWithMessage creates an ACK message from an existing message, extracting relevant fields.
func NewAckWithMessage(msg message.Message) Ack {
	return msg
}

// NewAckFromReader creates an ACK message by reading and parsing a message from the provided reader.
func NewAckFromReader(r io.Reader) (Ack, error) {
	msg, err := message.NewMessageFromReader(r)
	if err != nil {
		return nil, err
	}
	return NewAckWithMessage(msg), nil
}

// NewAckFromBytes creates an ACK message by parsing a byte slice into a message.
func NewAckFromBytes(b []byte) (Ack, error) {
	return NewAckFromReader(bytes.NewReader(b))
}
