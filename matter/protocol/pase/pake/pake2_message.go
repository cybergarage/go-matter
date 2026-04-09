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
	"github.com/cybergarage/go-matter/matter/protocol/mrp"
	"github.com/cybergarage/go-matter/matter/protocol/pase/pbkdf"
)

type pake2Message struct {
	paramReq    pbkdf.ParamRequestMessage
	paramRes    pbkdf.ParamResponseMessage
	pake1       Pake1Message
	headerOps   []message.HeaderOption
	protocolOps []message.ProtocolHeaderOption
	pake2ReqOps []Pake2Option
	Message
	Pake2
}

// Pake2MessageOption defines a functional option for configuring the Pake2Message.
type Pake2MessageOption func(*pake2Message)

// WithPake2MessageParamRequestMessage sets the ParamRequestMessage in the Pake2Message, which is used to construct the Pake2 payload.
func WithPake2MessageParamRequestMessage(paramReq pbkdf.ParamRequestMessage) Pake2MessageOption {
	return func(m *pake2Message) {
		m.paramReq = paramReq
	}
}

// WithPake2MessageParamResponseMessage sets the ParamResponseMessage in the Pake2Message, which is used to construct the Pake2 payload.
func WithPake2MessageParamResponseMessage(paramRes pbkdf.ParamResponseMessage) Pake2MessageOption {
	return func(msg *pake2Message) {
		msg.paramRes = paramRes
		msg.protocolOps = append(msg.protocolOps,
			message.WithHeaderAckCounter(paramRes.MessageCounter()+1),
		)
	}
}

// WithPake2MessagePake1Message sets the Pake1Message in the Pake2Message, which is used to construct the Pake2 payload.
func WithPake2MessagePake1Message(pake1 Pake1Message) Pake2MessageOption {
	return func(msg *pake2Message) {
		msg.pake1 = pake1
		refSrcNodeID, hasRefSrcNodeID := pake1.SourceNodeID()
		if hasRefSrcNodeID {
			msg.headerOps = append(msg.headerOps, message.WithHeaderDestinationNodeID(refSrcNodeID))
		}
		msg.protocolOps = append(msg.protocolOps,
			message.WithHeaderExchangeID(pake1.ExchangeID()),
			message.WithHeaderAckCounter(pake1.MessageCounter()),
		)
	}
}

// WithPake2MessagePake1Ack sets the AckCounter in the Pake2Message based on the given Pake1 Ack, which is used to construct the Pake2 payload. This is important for ensuring that the Pake2 message correctly acknowledges the Pake1 message and maintains the proper message counter sequence.
func WithPake2MessagePake1Ack(ack mrp.Ack) Pake2MessageOption {
	return func(msg *pake2Message) {
		msg.headerOps = append(msg.headerOps,
			message.WithHeaderMessageCounter(ack.MessageCounter()+1),
		)
		msg.protocolOps = append(msg.protocolOps,
			message.WithHeaderAckCounter(ack.MessageCounter()+1),
		)
	}
}

// NewPake2MessageFromBytes creates a new Pake2Message from the given byte slice, which is expected to be a valid message containing a Pake2 payload.
func NewPake2MessageFromBytes(data []byte) (Pake2Message, error) {
	msg, err := message.NewMessageFromBytes(data)
	if err != nil {
		return nil, err
	}
	pake, err := NewPake2FromBytes(msg.Payload())
	if err != nil {
		return nil, err
	}
	return &pake2Message{
		headerOps:   nil,
		protocolOps: nil,
		pake2ReqOps: nil,
		Message:     msg,
		Pake2:       pake,
	}, nil
}

// NewPake2Message creates a new Pake2Message using the provided options.
func NewPake2Message(opts ...any) (Pake2Message, error) {
	msg := &pake2Message{
		headerOps: []message.HeaderOption{
			message.WithHeaderSessionID(0x0000),
			message.WithHeaderSecurityFlags(0x00),
			message.WithHeaderMessageCounter(message.NewMessageCounter()),
		},
		protocolOps: []message.ProtocolHeaderOption{
			// 4.10. Message Exchanges
			message.WithHeaderExchangeFlags(message.ReliabilityFlag | message.AckFlag),
			// 4.11.1. Secure Channel Protocol Messages
			message.WithHeaderOpcode(message.PASEPake2),
			// 4.4.3.4. Protocol ID (16 bits)
			message.WithHeaderProtocolID(message.SecureChannel),
		},
		pake2ReqOps: []Pake2Option{},
		Message:     nil,
		Pake2:       nil,
	}

	for _, opt := range opts {
		switch opt := opt.(type) {
		case message.HeaderOption:
			msg.headerOps = append(msg.headerOps, opt)
		case message.ProtocolHeaderOption:
			msg.protocolOps = append(msg.protocolOps, opt)
		case Pake2Option:
			msg.pake2ReqOps = append(msg.pake2ReqOps, opt)
		case Pake2MessageOption:
			opt(msg)
		default:
			return nil, errInvalidOption(opt)
		}
	}

	computePB := func(paramRequest pbkdf.ParamRequestMessage, paramResponse pbkdf.ParamResponseMessage) ([]byte, []byte, []byte, error) {
		if msg.paramReq == nil {
			return nil, nil, nil, errInvalidParam("paramRequest", msg.paramReq)
		}
		if msg.paramRes == nil {
			return nil, nil, nil, errInvalidParam("paramResponse", msg.paramRes)
		}
		passcodeId := msg.paramReq.PasscodeID()
		salt, ok := msg.paramRes.PBKDFParams().Salt()
		if !ok {
			return nil, nil, nil, errInvalidParam("paramResponse.Salt", salt)
		}
		iterations, ok := msg.paramRes.PBKDFParams().Iterations()
		if !ok {
			return nil, nil, nil, errInvalidParam("paramResponse.Iterations", iterations)
		}
		w0, l, err := crypto.CryptoPAKEValuesResponder(
			passcodeId.Bytes(),
			salt,
			iterations,
		)
		if err != nil {
			return nil, nil, nil, err
		}
		pB, err := crypto.CryptoPB(w0, l)
		if err != nil {
			return nil, nil, nil, err
		}
		return w0, l, pB, nil
	}

	computeCB := func(paramRequest pbkdf.ParamRequestMessage, paramResponse pbkdf.ParamResponseMessage, pake1 Pake1Message, w0, pB []byte) ([]byte, error) {
		if paramRequest == nil {
			return nil, errInvalidParam("paramRequest", paramRequest)
		}
		if paramResponse == nil {
			return nil, errInvalidParam("paramResponse", paramResponse)
		}
		if pake1 == nil {
			return nil, errInvalidParam("pake1", pake1)
		}

		pA := pake1.pA()
		if len(pA) == 0 {
			return nil, errInvalidParam("pake1.pA", pA)
		}

		// The current PAKE implementation does not retain the ephemeral SPAKE2+
		// shared points, so use the exchanged public values as stable stand-ins
		// until the full shared-point derivation is wired in.
		tt, err := crypto.CryptoTranscript(
			paramRequest.Payload(),
			paramResponse.Payload(),
			pA,
			pB,
			pA,
			pB,
			w0,
		)
		if err != nil {
			return nil, err
		}

		_, cB, _, err := crypto.CryptoP2(tt, pA, pB)
		if err != nil {
			return nil, err
		}
		return cB, nil
	}

	// pB
	w0, _, pB, err := computePB(msg.paramReq, msg.paramRes)
	if err != nil {
		return nil, err
	}
	msg.pake2ReqOps = append(msg.pake2ReqOps, WithPake2PB(pB))

	// pC
	cB, err := computeCB(msg.paramReq, msg.paramRes, msg.pake1, w0, pB)
	if err != nil {
		return nil, err
	}
	msg.pake2ReqOps = append(msg.pake2ReqOps, WithPake2CB(cB))

	msg.Pake2 = NewPake2(msg.pake2ReqOps...)
	payload, err := msg.Pake2.Bytes()
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

func (m *pake2Message) Bytes() ([]byte, error) {
	return m.Message.Bytes()
}

func (m *pake2Message) Map() map[string]any {
	return map[string]any{
		"message":       m.Message.Map(),
		"pake-2-struct": m.Pake2.Map(),
	}
}

func (m *pake2Message) String() string {
	return json.MustMarshal(m.Map())
}
