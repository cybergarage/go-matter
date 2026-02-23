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

package pase

import (
	"github.com/cybergarage/go-matter/matter/encoding/message"
	"github.com/cybergarage/go-matter/matter/protocol/pase/pbkdf"
	"github.com/cybergarage/go-matter/matter/types"
)

// Message represents a complete message with frame header, protocol header, and payload.
// 4.4. Message Frame Format.
type Message = message.Message

// NewPBKDBParamRequestMessage creates a new PASE PBKDF Parameter Request message with the given options.
func NewPBKDBParamRequestMessage(opts ...any) (Message, error) {
	// 4.14.1.1. Protocol Overview

	headerOps := []message.HeaderOption{
		message.WithHeaderFlags(message.SourceNodeIDPresentFlag),
		message.WithHeaderSessionID(0x0000),
		message.WithHeaderSecurityFlags(0x00),
		message.WithHeaderMessageCounter(message.NewMessageCounter()),
		message.WithHeaderSourceNodeID(types.NewOperationalNodeID()),
	}

	protocolOps := []message.ProtocolHeaderOption{
		message.WithHeaderExchangeFlags(message.InitiatorFlag | message.ReliabilityFlag), // 4.10. Message Exchanges
		message.WithHeaderOpcode(message.PBKDFParamRequest),                              // 4.11.1. Secure Channel Protocol Messages.
		message.WithHeaderExchangeID(message.NewFirstExchangeID()),                       // 4.10.2. Exchange ID
		message.WithHeaderProtocolID(message.SecureChannel),                              // 4.4.3.4. Protocol ID (16 bits)
	}

	paramOps := []pbkdf.ParamRequestOption{}

	for _, opt := range opts {
		switch opt := opt.(type) {
		case message.HeaderOption:
			headerOps = append(headerOps, opt)
		case message.ProtocolHeaderOption:
			protocolOps = append(protocolOps, opt)
		case pbkdf.ParamRequestOption:
			paramOps = append(paramOps, opt)
		}
	}

	paramReq := pbkdf.NewParamRequest(paramOps...)
	payload, err := paramReq.Bytes()
	if err != nil {
		return nil, err
	}

	return message.NewMessage(
		message.WithMessageFrameHeader(message.NewHeader(headerOps...)),
		message.WithMessageProtocolHeader(message.NewProtocolHeader(protocolOps...)),
		message.WithMessagePayload(payload),
	), nil
}
