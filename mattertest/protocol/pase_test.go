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
	"bytes"
	"fmt"
	"testing"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter/encoding/message"
	"github.com/cybergarage/go-matter/matter/protocol/mrp"
	"github.com/cybergarage/go-matter/matter/protocol/pase/pbkdf"
)

func TestPaseSequence(t *testing.T) {
	log.EnableStdoutDebug(true)

	var err error
	reqMsgCounter := message.NewMessageCounter()
	// resMsgCounter := message.NewMessageCounter()

	tests := []struct {
		pbkdfParamReq    pbkdf.ParamRequestMessage
		pbkdfParamReqAck mrp.Ack
		pbkdfParamRes    pbkdf.ParamResponseMessage
	}{
		{
			pbkdfParamReq:    decodeHexdumpPBKDFParamRequestMessage(t, pbkdfParamRequest01Hex),
			pbkdfParamReqAck: decodeHexdumpMRPAck(t, pbkdfParamRequestAck01Hex),
			pbkdfParamRes:    decodeHexdumpPBKDFParamResponseMessage(t, pbkdfParamResponse01Hex),
		},
		{
			pbkdfParamReq: func() pbkdf.ParamRequestMessage {
				msg, err := pbkdf.NewParamRequestMessage(
					pbkdf.WithParamRequestMessageCounter(reqMsgCounter),
				)
				if err != nil {
					t.Fatal(err)
				}
				return msg
			}(),
			pbkdfParamReqAck: nil,
			pbkdfParamRes:    nil,
		},
	}

	// 4.14.1. Passcode-Authenticated Session Establishment (PASE)
	// 4.14.1.2. Protocol Details

	for n, tt := range tests {
		name := fmt.Sprintf("pase-%02d", n)
		t.Run(name, func(t *testing.T) {
			// PBKDF Parameter Request
			name := fmt.Sprintf("pbkdf-param-request-%02d", n)
			pbkdfParamReq := tt.pbkdfParamReq
			t.Run(name, func(t *testing.T) {
				if err := validatePBKDFParamRequest(pbkdfParamReq); err != nil {
					t.Errorf("Validation failed: %v", err)
				}
				log.Infof("%s %s", name, pbkdfParamReq.String())
			})

			// PBKDF Parameter Request Ack
			name = fmt.Sprintf("pbkdf-param-request-ack-%02d", n)
			pbkdfParamReqAck := tt.pbkdfParamReqAck
			t.Run(name, func(t *testing.T) {
				if pbkdfParamReqAck == nil {
					pbkdfParamReqAck, err = mrp.NewAck(
						mrp.WithAckReferenceMessage(pbkdfParamReq),
						mrp.WithAckMessageCounter(reqMsgCounter),
					)
				}

				// Validate the ACK message

				if err := validateAckMessage(pbkdfParamReqAck); err != nil {
					t.Errorf("Validation failed: %v", err)
				}

				// Validate that the ACK corresponds to the request

				sourceNodeIDReq, hasSourceNodeIDReq := pbkdfParamReq.SourceNodeID()
				destNodeIDRes, hasDestNodeIDRes := pbkdfParamReqAck.DestinationNodeID()
				if !hasSourceNodeIDReq || !hasDestNodeIDRes {
					t.Errorf("Missing Node ID: request hasSourceNodeID %v, response hasDestinationNodeID %v", hasSourceNodeIDReq, hasDestNodeIDRes)
				} else if sourceNodeIDReq != destNodeIDRes {
					t.Errorf("Node ID mismatch: request source %d, response destination %d", sourceNodeIDReq, destNodeIDRes)
				}

				ackCounter, hasAckCounter := pbkdfParamReqAck.AckMessageCounter()
				reqMsgCounter := pbkdfParamReq.MessageCounter()
				if !hasAckCounter {
					t.Error("Expected ACK to have message counter")
				} else if ackCounter != reqMsgCounter {
					t.Errorf("ACK message counter mismatch: got %d, want %d", ackCounter, reqMsgCounter)
				}

				if pbkdfParamReqAck.ExchangeID() != pbkdfParamReq.ExchangeID() {
					t.Errorf("ACK ExchangeID mismatch: got 0x%04X, want 0x%04X", pbkdfParamReqAck.ExchangeID(), pbkdfParamReq.ExchangeID())
				}

				log.Infof("%s %s", name, pbkdfParamReqAck.String())
			})

			// PBKDF Parameter Response
			name = fmt.Sprintf("pbkdf-param-response-%02d", n)
			pbkdfParamRes := tt.pbkdfParamRes
			t.Run(name, func(t *testing.T) {
				if pbkdfParamRes == nil {
					pbkdfParamRes, err = pbkdf.NewParamResponseMessage(
						pbkdf.WithParamResponseMessageParamRequestMessage(pbkdfParamReq),
					)
					if err != nil {
						t.Fatalf("Failed to create ParamResponseMessage: %v", err)
					}
				}

				// Validate the response message

				if err := validatePBKDFParamResponse(pbkdfParamRes); err != nil {
					t.Errorf("Validation failed: %v", err)
				}

				// Validate that the response corresponds to the request

				if pbkdfParamReq.ExchangeID() != pbkdfParamRes.ExchangeID() {
					t.Errorf("Exchange ID mismatch: request %d, response %d", pbkdfParamReq.ExchangeID(), pbkdfParamRes.ExchangeID())
				}

				sourceNodeIDReq, hasSourceNodeIDReq := pbkdfParamReq.SourceNodeID()
				destNodeIDRes, hasDestNodeIDRes := pbkdfParamRes.DestinationNodeID()
				if !hasSourceNodeIDReq || !hasDestNodeIDRes {
					t.Errorf("Missing Node ID: request hasSourceNodeID %v, response hasDestinationNodeID %v", hasSourceNodeIDReq, hasDestNodeIDRes)
				} else if sourceNodeIDReq != destNodeIDRes {
					t.Errorf("Node ID mismatch: request source %d, response destination %d", sourceNodeIDReq, destNodeIDRes)
				}

				if !bytes.Equal(pbkdfParamRes.InitiatorRandom(), pbkdfParamReq.InitiatorRandom()) {
					t.Errorf("Initiator Random mismatch: request %s, response %s", pbkdfParamReq.InitiatorRandom(), pbkdfParamRes.InitiatorRandom())
				}

				if pbkdfParamRes.ResponderSessionID() == uint16(pbkdfParamReq.InitiatorSessionID()) {
					t.Errorf("Responder Session ID should not match Initiator Session ID: got %d", pbkdfParamRes.ResponderSessionID())
				}

				log.Infof("%s %s", name, pbkdfParamRes.String())
			})
		})
	}
}
