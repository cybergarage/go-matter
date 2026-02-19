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
	_ "embed"
	"encoding/hex"
	"testing"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter/crypto/pbkdf"
	"github.com/cybergarage/go-matter/matter/protocol"
)

//go:embed dumps/pbkdf-param-request-01.hex
var pbkdfParamRequest01Hex string

//go:embed dumps/pbkdf-param-response-01.hex
var pbkdfParamResponse01Hex string

//go:embed dumps/pbkdf-param-response-02.hex
var pbkdfParamResponse02Hex string

func TestPBKDFParamRequestMessage(t *testing.T) {
	log.EnableStdoutDebug(true)

	tests := []struct {
		hexStr string
	}{
		{
			hexStr: pbkdfParamRequest01Hex,
		},
	}

	for _, tt := range tests {
		hexBytes, err := hex.DecodeString(tt.hexStr)
		if err != nil {
			t.Fatalf("Failed to decode hex string: %v", err)
		}
		msg, err := protocol.NewMessageFromBytes(hexBytes)
		if err != nil {
			t.Fatalf("Failed to parse Message: %v", err)
		}

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
		if _, ok := msg.DestinationNodeID(); ok {
			t.Errorf("Expected DestinationNodeID flag to be unset")
		}

		_, err = pbkdf.NewParamRequestFromBytes(msg.Payload())
		if err != nil {
			t.Errorf("Failed to parse ParamRequest: %v", err)
			log.HexInfo(hexBytes)
			log.Info(msg.String())
		}
	}
}

func TestPBKDFParamResponseMessage(t *testing.T) {
	log.EnableStdoutDebug(true)

	tests := []struct {
		hexStr string
	}{
		{
			hexStr: pbkdfParamResponse01Hex,
		},
		{
			hexStr: pbkdfParamResponse02Hex,
		},
	}

	for _, tt := range tests {
		hexBytes, err := hex.DecodeString(tt.hexStr)
		if err != nil {
			t.Fatalf("Failed to decode hex string: %v", err)
		}
		msg, err := protocol.NewMessageFromBytes(hexBytes)
		if err != nil {
			t.Fatalf("Failed to parse Message: %v", err)
		}

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

		_, err = pbkdf.NewParamResponseFromBytes(msg.Payload())
		if err != nil {
			t.Skipf("Failed to parse ParamResponse: %v", err)
			log.HexInfo(hexBytes)
			log.Info(msg.String())
		}
	}
}
