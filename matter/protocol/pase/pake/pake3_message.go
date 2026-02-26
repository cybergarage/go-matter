// Copyright (C) 2025 The go-matter Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pake

import (
	"github.com/cybergarage/go-matter/matter/encoding/json"
	"github.com/cybergarage/go-matter/matter/encoding/message"
	"github.com/cybergarage/go-matter/matter/types"
)

type pake3Message struct {
	headerOps   []message.HeaderOption
	protocolOps []message.ProtocolHeaderOption
	pake3ReqOps []Pake3Option
	Message
	Pake3
}

// Pake3MessageOption defines a functional option for configuring the Pake3Message.
type Pake3MessageOption func(*pake3Message)

func WithPake3MessagePake2Message(pake2 Pake2Message) Pake3MessageOption {
	return func(m *pake3Message) {
		// 4.10.2. Exchange ID
		m.protocolOps = append(m.protocolOps,
			message.WithHeaderExchangeID(pake2.ExchangeID()),
		)
	}
}

// WithPake3MessageMessageCounter sets the message counter in the Pake3Message.
func WithPake3MessageMessageCounter(counter message.MessageCounter) Pake3MessageOption {
	return func(m *pake3Message) {
		m.headerOps = append(m.headerOps, message.WithHeaderMessageCounter(counter))
	}
}

// NewPake3MessageFromBytes creates a new Pake3Message from the given byte slice, which is expected to be a valid message containing a Pake3 payload.
func NewPake3MessageFromBytes(data []byte) (Pake3Message, error) {
	msg, err := message.NewMessageFromBytes(data)
	if err != nil {
		return nil, err
	}
	pake, err := NewPake3FromBytes(msg.Payload())
	if err != nil {
		return nil, err
	}
	return &pake3Message{
		headerOps:   nil,
		protocolOps: nil,
		pake3ReqOps: nil,
		Message:     msg,
		Pake3:       pake,
	}, nil
}

func NewPake3Message(opts ...any) (Pake3Message, error) {
	msg := &pake3Message{
		headerOps: []message.HeaderOption{
			message.WithHeaderSessionID(0x0000),
			message.WithHeaderSecurityFlags(0x00),
			message.WithHeaderMessageCounter(message.NewMessageCounter()),
			message.WithHeaderSourceNodeID(types.NewOperationalNodeID()),
		},
		protocolOps: []message.ProtocolHeaderOption{
			// 4.10. Message Exchanges
			message.WithHeaderExchangeFlags(message.InitiatorFlag | message.ReliabilityFlag),
			// 4.11.1. Secure Channel Protocol Messages
			message.WithHeaderOpcode(message.PASEPake3),
			// 4.10.2. Exchange ID
			message.WithHeaderExchangeID(message.NewFirstExchangeID()),
			// 4.4.3.4. Protocol ID (16 bits)
			message.WithHeaderProtocolID(message.SecureChannel),
		},
		pake3ReqOps: []Pake3Option{},
		Message:     nil,
		Pake3:       nil,
	}

	for _, opt := range opts {
		switch opt := opt.(type) {
		case message.HeaderOption:
			msg.headerOps = append(msg.headerOps, opt)
		case message.ProtocolHeaderOption:
			msg.protocolOps = append(msg.protocolOps, opt)
		case Pake3Option:
			msg.pake3ReqOps = append(msg.pake3ReqOps, opt)
		case Pake3MessageOption:
			opt(msg)
		default:
			return nil, errInvalidOption(opt)
		}
	}

	msg.Pake3 = NewPake3(msg.pake3ReqOps...)
	payload, err := msg.Pake3.Bytes()
	if err != nil {
		return nil, err
	}

	msg.Message = message.NewMessage(
		message.WithMessageFrameHeader(message.NewHeader(msg.headerOps...)),
		message.WithMessageProtocolHeader(message.NewProtocolHeader(msg.protocolOps...)),
		message.WithMessagePayload(payload),
	)

	return msg, nil
}

func (m *pake3Message) Bytes() ([]byte, error) {
	return m.Message.Bytes()
}

func (m *pake3Message) Map() map[string]any {
	return map[string]any{
		"message":       m.Message.Map(),
		"pake-3-struct": m.Pake3.Map(),
	}
}

func (m *pake3Message) String() string {
	return json.MustMarshal(m.Map())
}
