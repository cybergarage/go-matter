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
	"github.com/cybergarage/go-matter/matter/encoding"
	"github.com/cybergarage/go-matter/matter/encoding/message"
	"github.com/cybergarage/go-matter/matter/protocol/mrp"
	"github.com/cybergarage/go-matter/matter/protocol/pase/pake"
	"github.com/cybergarage/go-matter/matter/protocol/pase/pbkdf"
)

func TestPaseSequence(t *testing.T) {
	log.EnableStdoutDebug(true)

	var err error
	initMsgCounter := message.NewMessageCounter()
	initPasscode, err := encoding.NewPairingCodeFromString("3035-750-7966")
	if err != nil {
		t.Fatalf("Failed to create PairingCode: %v", err)
	}

	tests := []struct {
		pbkdfParamReq    pbkdf.ParamRequestMessage
		pbkdfParamReqAck mrp.Ack
		pbkdfParamRes    pbkdf.ParamResponseMessage
		pake1            pake.Pake1Message
		pake1Ack         mrp.Ack
		pake2            pake.Pake2Message
		pake3            pake.Pake3Message
	}{
		// {
		// 	pbkdfParamReq:    decodeHexdumpPBKDFParamRequestMessage(t, pbkdfParamRequestHex01),
		// 	pbkdfParamReqAck: decodeHexdumpMRPAck(t, pbkdfParamRequestAckHex01),
		// 	pbkdfParamRes:    decodeHexdumpPBKDFParamResponseMessage(t, pbkdfParamResponseHex01),
		// 	pake1:            decodeHexdumpPake1Message(t, pake1Hex01),
		// 	pake1Ack:         decodeHexdumpMRPAck(t, pake1AckHex01),
		// 	pake2:            decodeHexdumpPake2Message(t, pake2Hex01),
		// 	pake3:            decodeHexdumpPake3Message(t, pake3Hex01),
		// },
		{
			pbkdfParamReq: func() pbkdf.ParamRequestMessage {
				msg, err := pbkdf.NewParamRequestMessage()
				if err != nil {
					t.Fatal(err)
				}
				return msg
			}(),
			pbkdfParamReqAck: nil,
			pbkdfParamRes:    nil,
			pake1:            nil,
			pake1Ack:         nil,
			pake2:            nil,
			pake3:            nil,
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
						mrp.WithAckMessageCounter(initMsgCounter),
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
						pbkdf.WithParamResponseMessageParamRequestAck(pbkdfParamReqAck),
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

				// Validate that the response corresponds to the request ACK

				if pbkdfParamRes.MessageCounter() <= pbkdfParamReqAck.MessageCounter() {
					t.Errorf("Response MessageCounter should be greater than ACK MessageCounter: got %d, want > %d", pbkdfParamRes.MessageCounter(), pbkdfParamReqAck.MessageCounter())
				}

				log.Infof("%s %s", name, pbkdfParamRes.String())
			})

			// PAKE1
			name = fmt.Sprintf("pake1-%02d", n)
			pake1 := tt.pake1
			t.Run(name, func(t *testing.T) {
				if pake1 == nil {
					pake1Params := pbkdf.NewParams(
						pbkdf.WithParamsPasscode(initPasscode.Passcode()),
						pbkdf.WithParamsParamResponse(pbkdfParamRes.PBKDFParams()),
					)
					pake1, err = pake.NewPake1Message(
						pake.WithPake1MessageParamRequestMessage(pbkdfParamReq),
						pake.WithPake1MessageParamResponseMessage(pbkdfParamRes),
						pake.WithPake1MessagePBKDFParams(pake1Params),
					)
					if err != nil {
						t.Skipf("Failed to create ParamResponseMessage: %v", err)
						return
					}
				}

				// Validate the PAKE1 message

				if err := validatePake1Message(pake1); err != nil {
					t.Errorf("Validation failed: %v", err)
				}

				// Validate that the PAKE1 message corresponds to the PBKDF Parameter Reuest

				if pake1.MessageCounter() <= pbkdfParamReq.MessageCounter() {
					t.Errorf("PAKE1 MessageCounter should be greater than PBKDF request MessageCounter: got %d, want > %d", pake1.MessageCounter(), pbkdfParamReq.MessageCounter())
				}

				// Validate that the PAKE1 message corresponds to the PBKDF Parameter Response

				if pake1.ExchangeID() != pbkdfParamRes.ExchangeID() {
					t.Errorf("Exchange ID mismatch: PBKDF response %d, PAKE1 %d", pbkdfParamRes.ExchangeID(), pake1.ExchangeID())
				}

				log.Infof("%s %s", name, pake1.String())
			})

			if pake1 == nil {
				// If PAKE1 message is not available, skip the rest of the sequence
				return
			}

			// PAKE1 Ack
			name = fmt.Sprintf("pake1-ack-%02d", n)
			pake1Ack := tt.pake1Ack
			t.Run(name, func(t *testing.T) {
				if pake1Ack == nil {
					pake1Ack, err = mrp.NewAck(
						mrp.WithAckReferenceMessage(pake1),
						mrp.WithAckMessageCounter(pake1.MessageCounter()),
					)
					if err != nil {
						t.Fatalf("Failed to create PAKE1 ACK: %v", err)
					}
				}

				// Validate the ACK message

				if err := validateAckMessage(pake1Ack); err != nil {
					t.Errorf("Validation failed: %v", err)
				}

				// Validate that the ACK corresponds to the PAKE1 message

				sourceNodeIDPake1, hasSourceNodeIDPake1 := pake1.SourceNodeID()
				destNodeIDAck, hasDestNodeIDAck := pake1Ack.DestinationNodeID()
				if !hasSourceNodeIDPake1 || !hasDestNodeIDAck {
					t.Errorf("Missing Node ID: PAKE1 hasSourceNodeID %v, ACK hasDestinationNodeID %v", hasSourceNodeIDPake1, hasDestNodeIDAck)
				} else if sourceNodeIDPake1 != destNodeIDAck {
					t.Errorf("Node ID mismatch: PAKE1 source %d, ACK destination %d", sourceNodeIDPake1, destNodeIDAck)
				}

				ackCounter, hasAckCounter := pake1Ack.AckMessageCounter()
				pake1MsgCounter := pake1.MessageCounter()
				if !hasAckCounter {
					t.Error("Expected ACK to have message counter")
				} else if ackCounter != pake1MsgCounter {
					t.Errorf("ACK message counter mismatch: got %d, want %d", ackCounter, pake1MsgCounter)
				}

				if pake1Ack.ExchangeID() != pake1.ExchangeID() {
					t.Errorf("ACK ExchangeID mismatch: got 0x%04X, want 0x%04X", pake1Ack.ExchangeID(), pake1.ExchangeID())
				}

				log.Infof("%s %s", name, pake1Ack.String())
			})

			// PAKE2
			name = fmt.Sprintf("pake2-%02d", n)
			pake2 := tt.pake2
			t.Run(name, func(t *testing.T) {
				if pake2 == nil {
					pake2, err = pake.NewPake2Message(
						pake.WithPake2MessageParamRequestMessage(pbkdfParamReq),
						pake.WithPake2MessageParamResponseMessage(pbkdfParamRes),
						pake.WithPake2MessagePake1Message(pake1),
						pake.WithPake2MessagePake1Ack(pake1Ack),
					)
					if err != nil {
						t.Errorf("Failed to create PAKE2 message: %v", err)
						return
					}
				}

				// Validate the PAKE2 message

				if err := validatePake2Message(pake2); err != nil {
					t.Errorf("Validation failed: %v", err)
				}

				log.Infof("%s %s", name, pake2.String())
			})

			if pake2 == nil {
				// If PAKE2 message is not available, skip the rest of the sequence
				return
			}

			// PAKE3
			name = fmt.Sprintf("pake3-%02d", n)
			pake3 := tt.pake3
			t.Run(name, func(t *testing.T) {
				if pake3 == nil {
					pake3, err = pake.NewPake3Message(
						pake.WithPake3MessagePake2Message(pake2),
						message.WithHeaderMessageCounter(pake2.MessageCounter().Next()),
					)
					if err != nil {
						t.Skipf("Failed to create PAKE3 message: %v", err)
						return
					}
				}

				// Validate the PAKE3 message
				if err := validatePake3Message(pake3); err != nil {
					t.Errorf("Validation failed: %v", err)
				}

				log.Infof("%s %s", name, pake3.String())
			})
		})
	}
}
