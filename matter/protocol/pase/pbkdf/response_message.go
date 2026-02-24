// Copyright (C) 2025 The go-matter Authors. All rights reserved.
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

package pbkdf

import (
	"github.com/cybergarage/go-matter/matter/encoding/json"
	"github.com/cybergarage/go-matter/matter/encoding/message"
	"github.com/cybergarage/go-matter/matter/types"
)

type paramResponseMessage struct {
	headerOps   []message.HeaderOption
	protocolOps []message.ProtocolHeaderOption
	paramResOps []ParamResponseOption
	Message
	ParamResponse
}

// ParamResponseMessageOption defines a functional option for configuring the ParamResponseMessage.
type ParamResponseMessageOption func(*paramResponseMessage)

// WithParamResponseMessageParamRequestMessage sets the protocol header options in the ParamResponseMessage based on the given ParamRequestMessage.
func WithParamResponseMessageParamRequestMessage(paramReqMsg ParamRequestMessage) ParamResponseMessageOption {
	return func(m *paramResponseMessage) {
		// 4.14.1.2. Protocol Details
		if sourceNodeID, ok := paramReqMsg.SourceNodeID(); ok {
			m.headerOps = append(m.headerOps,
				message.WithHeaderDestinationNodeID(sourceNodeID),
			)
		}
		m.paramResOps = append(m.paramResOps,
			// 4.13.2.4. Choosing Secure Unicast Session Identifiers
			WithParamResponseResponderSessionID(types.NewSessionIDExcept(paramReqMsg.InitiatorSessionID())),
		)
		m.paramResOps = append(m.paramResOps,
			WithParamResponseParamRequest(paramReqMsg),
		)
		// 4.10.2. Exchange ID
		m.protocolOps = append(m.protocolOps,
			message.WithHeaderExchangeID(paramReqMsg.ExchangeID()),
		)
	}
}

// NewParamResponseMessageFromBytes parses the given byte slice into a ParamResponseMessage.
func NewParamResponseMessageFromBytes(data []byte) (ParamResponseMessage, error) {
	msg, err := message.NewMessageFromBytes(data)
	if err != nil {
		return nil, err
	}

	paramReq, err := NewParamResponseFromBytes(msg.Payload())
	if err != nil {
		return nil, err
	}

	return &paramResponseMessage{
		headerOps:     nil,
		protocolOps:   nil,
		paramResOps:   nil,
		Message:       msg,
		ParamResponse: paramReq,
	}, nil
}

// NewParamResponseMessage creates a new ParamResponseMessage with the given options.
func NewParamResponseMessage(opts ...any) (ParamResponseMessage, error) {
	// 4.14.1.1. Protocol Overview

	msg := &paramResponseMessage{
		headerOps: []message.HeaderOption{
			message.WithHeaderFlags(message.DestinationNodeIDPresentFlag),
			message.WithHeaderSessionID(0x0000),
			message.WithHeaderSecurityFlags(0x00),
			message.WithHeaderMessageCounter(message.NewMessageCounter()),
		},
		protocolOps: []message.ProtocolHeaderOption{
			// 4.10. Message Exchanges
			message.WithHeaderExchangeFlags(message.AckFlag | message.ReliabilityFlag),
			// 4.11.1. Secure Channel Protocol Messages
			message.WithHeaderOpcode(message.PBKDFParamResponse),
			// 4.4.3.4. Protocol ID (16 bits)
			message.WithHeaderProtocolID(message.SecureChannel),
		},
		paramResOps:   []ParamResponseOption{},
		Message:       nil,
		ParamResponse: nil,
	}

	for _, opt := range opts {
		switch opt := opt.(type) {
		case message.HeaderOption:
			msg.headerOps = append(msg.headerOps, opt)
		case message.ProtocolHeaderOption:
			msg.protocolOps = append(msg.protocolOps, opt)
		case ParamResponseOption:
			msg.paramResOps = append(msg.paramResOps, opt)
		case ParamResponseMessageOption:
			opt(msg)
		default:
			return nil, errInvalidOption(opt)
		}
	}

	var err error
	msg.ParamResponse, err = NewParamResponse(msg.paramResOps...)
	if err != nil {
		return nil, err
	}

	payload, err := msg.ParamResponse.Bytes()
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

func (r *paramResponseMessage) Bytes() ([]byte, error) {
	return r.Message.Bytes()
}

func (r *paramResponseMessage) Map() map[string]any {
	return map[string]any{
		"message":              r.Message.Map(),
		"pbkdfparamres-struct": r.ParamResponse.Map(),
	}
}

func (r *paramResponseMessage) String() string {
	return json.MustMarshal(r.Map())
}
