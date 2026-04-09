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
	"github.com/cybergarage/go-matter/matter/crypto"
	"github.com/cybergarage/go-matter/matter/encoding/json"
	"github.com/cybergarage/go-matter/matter/encoding/message"
	"github.com/cybergarage/go-matter/matter/protocol/pase/pbkdf"
)

type pake1Message struct {
	headerOps   []message.HeaderOption
	protocolOps []message.ProtocolHeaderOption
	pake1ReqOps []Pake1Option
	Message
	Pake1
}

// Pake1MessageOption defines a functional option for configuring the Pake1Message.
type Pake1MessageOption func(*pake1Message) error

// WithPake1MessageParamRequestMessage sets the ParamRequestMessage in the Pake1Message, which is used to construct the Pake1 payload and also sets the appropriate header and protocol options based on the ParamRequestMessage.
func WithPake1MessageParamRequestMessage(paramReq pbkdf.ParamRequestMessage) Pake1MessageOption {
	return func(m *pake1Message) error {
		// Header options
		if sourceID, ok := paramReq.SourceNodeID(); ok {
			m.headerOps = append(m.headerOps, message.WithHeaderSourceNodeID(sourceID))
		}
		m.headerOps = append(m.headerOps, message.WithHeaderMessageCounter(paramReq.MessageCounter().Next()))
		// Protocol options
		m.protocolOps = append(m.protocolOps, message.WithHeaderExchangeID(paramReq.ExchangeID()))
		return nil
	}
}

// WithPake1MessageParamResponseMessage sets the ParamResponseMessage in the Pake1Message, which is used to construct the Pake1 payload.
func WithPake1MessageParamResponseMessage(paramRes pbkdf.ParamResponseMessage) Pake1MessageOption {
	return func(m *pake1Message) error {
		// Protocol options
		m.protocolOps = append(m.protocolOps, message.WithHeaderAckCounter(paramRes.MessageCounter()))
		return nil
	}
}

// WithPake1MessagePBKDFParams is a convenience option that sets the ParamResponseMessage in the Pake1Message using the given PBKDF parameters, which is used to construct the Pake1 payload. This is useful when you have the PBKDF parameters but not the full ParamResponseMessage, and it will internally create a ParamResponseMessage with the given parameters and use it to set the appropriate protocol options and construct the Pake1 payload.
func WithPake1MessagePBKDFParams(resParams pbkdf.Params) Pake1MessageOption {
	return func(m *pake1Message) error {
		// 4.14.1.2. Protocol Details
		passwd, ok := resParams.Password()
		if !ok {
			return errInvalidParam("passcode", nil)
		}
		salt, ok := resParams.Salt()
		if !ok {
			return errInvalidParam("salt", nil)
		}
		iterations, ok := resParams.Iterations()
		if !ok {
			return errInvalidParam("iterations", nil)
		}
		w0, w1, err := crypto.CryptoPAKEValuesInitiator(passwd, salt, iterations)
		if err != nil {
			return err
		}
		pA, err := crypto.CryptoPA(w0, w1)
		if err != nil {
			return err
		}
		m.pake1ReqOps = append(m.pake1ReqOps, WithPake1PA(pA))
		return nil
	}
}

// NewPake1MessageFromBytes creates a new Pake1Message from the given byte slice, which is expected to be a valid message containing a Pake1 payload.
func NewPake1MessageFromBytes(data []byte) (Pake1Message, error) {
	msg, err := message.NewMessageFromBytes(data)
	if err != nil {
		return nil, err
	}
	pake, err := NewPake1FromBytes(msg.Payload())
	if err != nil {
		return nil, err
	}
	return &pake1Message{
		headerOps:   nil,
		protocolOps: nil,
		pake1ReqOps: nil,
		Message:     msg,
		Pake1:       pake,
	}, nil
}

// NewPake1Message creates a new Pake1Message using the provided options.
func NewPake1Message(opts ...any) (Pake1Message, error) {
	msg := &pake1Message{
		headerOps: []message.HeaderOption{
			message.WithHeaderSessionID(0x0000),
			message.WithHeaderSecurityFlags(0x00),
		},
		protocolOps: []message.ProtocolHeaderOption{
			// 4.10. Message Exchanges
			message.WithHeaderExchangeFlags(message.InitiatorFlag | message.AckFlag | message.ReliabilityFlag),
			// 4.11.1. Secure Channel Protocol Messages
			message.WithHeaderOpcode(message.PASEPake1),
			// 4.4.3.4. Protocol ID (16 bits)
			message.WithHeaderProtocolID(message.SecureChannel),
		},
		pake1ReqOps: []Pake1Option{},
		Message:     nil,
		Pake1:       nil,
	}

	for _, opt := range opts {
		switch opt := opt.(type) {
		case message.HeaderOption:
			msg.headerOps = append(msg.headerOps, opt)
		case message.ProtocolHeaderOption:
			msg.protocolOps = append(msg.protocolOps, opt)
		case Pake1Option:
			msg.pake1ReqOps = append(msg.pake1ReqOps, opt)
		case Pake1MessageOption:
			if err := opt(msg); err != nil {
				return nil, err
			}
		default:
			return nil, errInvalidOption(opt)
		}
	}

	msg.Pake1 = NewPake1(msg.pake1ReqOps...)
	payload, err := msg.Pake1.Bytes()
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

func (m *pake1Message) Bytes() ([]byte, error) {
	return m.Message.Bytes()
}

func (m *pake1Message) Map() map[string]any {
	return map[string]any{
		"message":       m.Message.Map(),
		"pake-1-struct": m.Pake1.Map(),
	}
}

func (m *pake1Message) String() string {
	return json.MustMarshal(m.Map())
}
