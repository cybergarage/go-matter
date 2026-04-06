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

type paramRequestMessage struct {
	headerOps   []message.HeaderOption
	protocolOps []message.ProtocolHeaderOption
	paramReqOps []ParamRequestOption
	Message
	ParamRequest
}

// ParamRequestMessageOption defines a functional option for configuring the ParamRequestMessage.
type ParamRequestMessageOption func(*paramRequestMessage)

// NewParamRequestMessageFromBytes parses the given byte slice into a ParamRequestMessage.
func NewParamRequestMessageFromBytes(data []byte) (ParamRequestMessage, error) {
	msg, err := message.NewMessageFromBytes(data)
	if err != nil {
		return nil, err
	}

	paramReq, err := NewParamRequestFromBytes(msg.Payload())
	if err != nil {
		return nil, err
	}

	return &paramRequestMessage{
		headerOps:    nil,
		protocolOps:  nil,
		paramReqOps:  nil,
		Message:      msg,
		ParamRequest: paramReq,
	}, nil
}

// NewParamRequestMessage creates a new PASE PBKDF Parameter Request message with the given options.
func NewParamRequestMessage(opts ...any) (ParamRequestMessage, error) {
	// 4.14.1.1. Protocol Overview

	msg := &paramRequestMessage{
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
			message.WithHeaderOpcode(message.PBKDFParamRequest),
			// 4.10.2. Exchange ID
			message.WithHeaderExchangeID(message.NewFirstExchangeID()),
			// 4.4.3.4. Protocol ID (16 bits)
			message.WithHeaderProtocolID(message.SecureChannel),
		},
		paramReqOps:  []ParamRequestOption{},
		Message:      nil,
		ParamRequest: nil,
	}

	for _, opt := range opts {
		switch opt := opt.(type) {
		case message.HeaderOption:
			msg.headerOps = append(msg.headerOps, opt)
		case message.ProtocolHeaderOption:
			msg.protocolOps = append(msg.protocolOps, opt)
		case ParamRequestOption:
			msg.paramReqOps = append(msg.paramReqOps, opt)
		case ParamRequestMessageOption:
			opt(msg)
		default:
			return nil, errInvalidOption(opt)
		}
	}

	msg.ParamRequest = NewParamRequest(msg.paramReqOps...)
	payload, err := msg.ParamRequest.Bytes()
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

func (r *paramRequestMessage) Bytes() ([]byte, error) {
	return r.Message.Bytes()
}

func (r *paramRequestMessage) Map() map[string]any {
	return map[string]any{
		"message":              r.Message.Map(),
		"pbkdfparamreq-struct": r.ParamRequest.Map(),
	}
}

func (r *paramRequestMessage) String() string {
	return json.MustMarshal(r.Map())
}
