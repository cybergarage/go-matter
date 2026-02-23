// Copyright (C) 2024 The go-matter Authors. All rights reserved.
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
	"fmt"
	"testing"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter/encoding/message"
	"github.com/cybergarage/go-matter/matter/protocol/pase/pbkdf"
)

func TestPBKDFParamRequestMessage(t *testing.T) {
	log.EnableStdoutDebug(true)

	tests := []struct {
		msg message.Message
	}{
		{
			msg: decodeHexdumpMessage(t, pbkdfParamRequest01Hex),
		},
		{
			msg: func() message.Message {
				msg, err := pbkdf.NewParamRequestMessage()
				if err != nil {
					t.Fatal(err)
				}
				return msg
			}(),
		},
	}

	for n, tt := range tests {
		name := fmt.Sprintf("pbkdf-param-request-%02d", n)
		t.Run(name, func(t *testing.T) {
			msg := tt.msg

			// 4.14.1. Passcode-Authenticated Session Establishment (PASE)
			// 4.14.1.2. Protocol Details
			if msg.SessionID() != 0x0000 {
				t.Errorf("Expected SessionID 0x0000, got 0x%04X", msg.SessionID())
			}
			if msg.SecurityFlags().SessionType() != 0x00 {
				t.Errorf("Expected SessionType 0x00, got 0x%02X", msg.SecurityFlags().SessionType())
			}
			if !msg.Flags().HasSourceNodeID() {
				t.Errorf("Expected SourceNodeID flag to be set")
			}
			sourceNodeID, ok := msg.SourceNodeID()
			if !ok || !sourceNodeID.IsOperational() {
				t.Errorf("Expected SourceNodeID to be operational, got %v", sourceNodeID)
			}
			if _, ok := msg.DestinationNodeID(); ok {
				t.Errorf("Expected DestinationNodeID flag to be unset")
			}
			if msg.Opcode() != message.PBKDFParamRequest {
				t.Errorf("Expected OpCode 0x%02X, got 0x%02X", message.PBKDFParamRequest, msg.Opcode())
			}
			if msg.ProtocolID() != message.SecureChannel {
				t.Errorf("Expected ProtocolID 0x%04X, got 0x%04X", message.SecureChannel, msg.ProtocolID())
			}
			if !msg.ExchangeFlags().IsInitiator() {
				t.Errorf("Expected ExchangeFlags Initiator to be set")
			}
			if !msg.ExchangeFlags().IsReliability() {
				t.Errorf("Expected ExchangeFlags Reliability to be set")
				log.Infof("Message: %s", msg.String())
			}
			exID := msg.ExchangeID()
			if exID == 0 {
				t.Errorf("Expected random ExchangeID, got 0x%04X", exID)
			}

			reqParam, err := pbkdf.NewParamRequestFromBytes(msg.Payload())
			if err != nil {
				t.Errorf("Failed to parse ParamRequest: %v", err)
			}
			log.Infof("%s %s", name, msg.String())
			log.Infof("%s %s", name, reqParam.String())
		})
	}
}

func TestPBKDFParamResponseMessage(t *testing.T) {
	log.EnableStdoutDebug(true)

	tests := []struct {
		msg message.Message
	}{
		{
			msg: decodeHexdumpMessage(t, pbkdfParamResponse01Hex),
		},
	}

	for n, tt := range tests {
		name := fmt.Sprintf("pbkdf-param-response-%02d", n)
		t.Run(name, func(t *testing.T) {
			msg := tt.msg

			// 4.14.1. Passcode-Authenticated Session Establishment (PASE)
			// 4.14.1.2. Protocol Details
			if msg.SessionID() != 0x0000 {
				t.Errorf("Expected SessionID 0x0000, got 0x%04X", msg.SessionID())
			}
			if msg.SecurityFlags().SessionType() != 0x00 {
				t.Errorf("Expected SessionType 0x00, got 0x%02X", msg.SecurityFlags().SessionType())
			}
			if msg.Flags().HasSourceNodeID() {
				t.Errorf("Expected SourceNodeID flag to be unset")
			}
			if _, ok := msg.DestinationNodeID(); !ok {
				t.Errorf("Expected DestinationNodeID flag to be set")
			}

			resParam, err := pbkdf.NewParamResponseFromBytes(msg.Payload())
			if err != nil {
				t.Errorf("Failed to parse ParamResponse: %v", err)
			}
			log.Infof("%s %s", name, msg.String())
			log.Infof("%s %s", name, resParam.String())
		})
	}
}
