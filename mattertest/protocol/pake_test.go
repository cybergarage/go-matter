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
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter/encoding"
	"github.com/cybergarage/go-matter/matter/protocol/mrp"
	"github.com/cybergarage/go-matter/matter/protocol/pase/pake"
	"github.com/cybergarage/go-matter/matter/protocol/pase/pbkdf"
)

func TestPake1Message(t *testing.T) {
	log.EnableStdoutDebug(true)

	tests := []struct {
		hexStr string
	}{
		{
			hexStr: pake1Hex01,
		},
	}

	for n, tt := range tests {
		t.Run(fmt.Sprintf("pake1-%02d", n), func(t *testing.T) {
			hexBytes, err := hex.DecodeString(tt.hexStr)
			if err != nil {
				t.Fatalf("Failed to decode hex string: %v", err)
			}
			msg, err := pake.NewPake1MessageFromBytes(hexBytes)
			if err != nil {
				t.Fatalf("Failed to parse Pake1Message: %v", err)
			}
			if err != nil {
				t.Errorf("Failed to parse ParamRequest: %v", err)
				log.HexInfo(hexBytes)
			}
			log.Infof("pake1: %s", msg.String())
		})
	}
}

func TestPake2Message(t *testing.T) {
	log.EnableStdoutDebug(true)

	tests := []struct {
		hexStr string
	}{
		{
			hexStr: pake2Hex01,
		},
	}

	for n, tt := range tests {
		t.Run(fmt.Sprintf("pake2-%02d", n), func(t *testing.T) {
			hexBytes, err := hex.DecodeString(tt.hexStr)
			if err != nil {
				t.Fatalf("Failed to decode hex string: %v", err)
			}
			msg, err := pake.NewPake2MessageFromBytes(hexBytes)
			if err != nil {
				t.Fatalf("Failed to parse Pake2Message: %v", err)
			}
			if err != nil {
				t.Errorf("Failed to parse ParamRequest: %v", err)
				log.HexInfo(hexBytes)
			}
			log.Infof("pake2: %s", msg.String())
		})
	}
}

func TestPake2MessageRequiresPake1ForCB(t *testing.T) {
	paramReq, err := pbkdf.NewParamRequestMessage()
	if err != nil {
		t.Fatalf("Failed to create ParamRequestMessage: %v", err)
	}

	paramReqAck, err := mrp.NewAck(
		mrp.WithAckReferenceMessage(paramReq),
	)
	if err != nil {
		t.Fatalf("Failed to create ParamRequest ACK: %v", err)
	}

	paramRes, err := pbkdf.NewParamResponseMessage(
		pbkdf.WithParamResponseMessageParamRequestMessage(paramReq),
		pbkdf.WithParamResponseMessageParamRequestAck(paramReqAck),
	)
	if err != nil {
		t.Fatalf("Failed to create ParamResponseMessage: %v", err)
	}

	_, err = pake.NewPake2Message(
		pake.WithPake2MessageParamRequestMessage(paramReq),
		pake.WithPake2MessageParamResponseMessage(paramRes),
	)
	if err == nil {
		t.Fatal("expected NewPake2Message to fail without a Pake1 message")
	}
}

func TestPake3Message(t *testing.T) {
	log.EnableStdoutDebug(true)

	tests := []struct {
		hexStr string
	}{
		{
			hexStr: pake3Hex01,
		},
	}

	for n, tt := range tests {
		t.Run(fmt.Sprintf("pake3-%02d", n), func(t *testing.T) {
			hexBytes, err := hex.DecodeString(tt.hexStr)
			if err != nil {
				t.Fatalf("Failed to decode hex string: %v", err)
			}
			msg, err := pake.NewPake3MessageFromBytes(hexBytes)
			if err != nil {
				t.Fatalf("Failed to parse Pake3Message: %v", err)
			}
			if err != nil {
				t.Errorf("Failed to parse ParamRequest: %v", err)
				log.HexInfo(hexBytes)
			}
			log.Infof("pake3: %s", msg.String())
		})
	}
}

func TestPake3MessageRequiresPake1AndPake2ForCA(t *testing.T) {
	paramReq, err := pbkdf.NewParamRequestMessage()
	if err != nil {
		t.Fatalf("Failed to create ParamRequestMessage: %v", err)
	}

	paramReqAck, err := mrp.NewAck(
		mrp.WithAckReferenceMessage(paramReq),
	)
	if err != nil {
		t.Fatalf("Failed to create ParamRequest ACK: %v", err)
	}

	paramRes, err := pbkdf.NewParamResponseMessage(
		pbkdf.WithParamResponseMessageParamRequestMessage(paramReq),
		pbkdf.WithParamResponseMessageParamRequestAck(paramReqAck),
	)
	if err != nil {
		t.Fatalf("Failed to create ParamResponseMessage: %v", err)
	}

	_, err = pake.NewPake3Message(
		pake.WithPake3MessageParamRequestMessage(paramReq),
		pake.WithPake3MessageParamResponseMessage(paramRes),
	)
	if err == nil {
		t.Fatal("expected NewPake3Message to fail without Pake1 and Pake2 messages")
	}

	pairingCode, err := encoding.NewPairingCodeFromString("3035-750-7966")
	if err != nil {
		t.Fatalf("Failed to create PairingCode: %v", err)
	}

	pake1Params := pbkdf.NewParams(
		pbkdf.WithParamsPasscode(pairingCode.Passcode()),
		pbkdf.WithParamsParamResponse(paramRes.PBKDFParams()),
	)
	pake1, err := pake.NewPake1Message(
		pake.WithPake1MessageParamRequestMessage(paramReq),
		pake.WithPake1MessageParamResponseMessage(paramRes),
		pake.WithPake1MessagePBKDFParams(pake1Params),
	)
	if err != nil {
		t.Fatalf("Failed to create Pake1Message: %v", err)
	}

	_, err = pake.NewPake3Message(
		pake.WithPake3MessageParamRequestMessage(paramReq),
		pake.WithPake3MessageParamResponseMessage(paramRes),
		pake.WithPake3MessagePake1Message(pake1),
	)
	if err == nil {
		t.Fatal("expected NewPake3Message to fail without a Pake2 message")
	}

	paramResAck, err := mrp.NewAck(
		mrp.WithAckReferenceMessage(pake1),
		mrp.WithAckPrecedingMessage(paramRes),
	)
	if err != nil {
		t.Fatalf("Failed to create Pake1 ACK: %v", err)
	}

	pake2, err := pake.NewPake2Message(
		pake.WithPake2MessagePake1Ack(paramResAck),
		pake.WithPake2MessageParamRequestMessage(paramReq),
		pake.WithPake2MessageParamResponseMessage(paramRes),
		pake.WithPake2MessagePake1Message(pake1),
	)
	if err != nil {
		t.Fatalf("Failed to create Pake2Message: %v", err)
	}

	_, err = pake.NewPake3Message(
		pake.WithPake3MessageParamRequestMessage(paramReq),
		pake.WithPake3MessageParamResponseMessage(paramRes),
		pake.WithPake3MessagePake2Message(pake2),
	)
	if err == nil {
		t.Fatal("expected NewPake3Message to fail without a Pake1 message")
	}
}
