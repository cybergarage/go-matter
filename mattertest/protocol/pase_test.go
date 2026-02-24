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
	"github.com/cybergarage/go-matter/matter/protocol/pase/pbkdf"
)

func TestPaseSequence(t *testing.T) {
	log.EnableStdoutDebug(true)

	tests := []struct {
		pbkdfParamReq pbkdf.ParamRequestMessage
		pbkdfParamRes pbkdf.ParamResponseMessage
	}{
		{
			pbkdfParamReq: decodeHexdumpPBKDFParamRequestMessage(t, pbkdfParamRequest01Hex),
			pbkdfParamRes: decodeHexdumpPBKDFParamResponseMessage(t, pbkdfParamResponse01Hex),
		},
		{
			pbkdfParamReq: func() pbkdf.ParamRequestMessage {
				msg, err := pbkdf.NewParamRequestMessage()
				if err != nil {
					t.Fatal(err)
				}
				return msg
			}(),
			pbkdfParamRes: nil,
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

			// PBKDF Parameter Response
			name = fmt.Sprintf("pbkdf-param-response-%02d", n)
			t.Run(name, func(t *testing.T) {
				var err error
				pbkdfParamRes := tt.pbkdfParamRes
				if pbkdfParamRes == nil {
					pbkdfParamRes, err = pbkdf.NewParamResponseMessage(
						pbkdf.WithParamResponseMessageParamRequestMessage(pbkdfParamReq),
					)
					if err != nil {
						t.Fatalf("Failed to create ParamResponseMessage: %v", err)
					}
				}

				if err := validatePBKDFParamResponse(pbkdfParamRes); err != nil {
					t.Errorf("Validation failed: %v", err)
				}

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
