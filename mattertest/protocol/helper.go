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

	"github.com/cybergarage/go-matter/matter/encoding/message"
	"github.com/cybergarage/go-matter/matter/protocol/pase/pbkdf"
)

func decodeHexdumpPBKDFParamRequestMessage(t *testing.T, hexStr string) pbkdf.ParamRequestMessage {
	t.Helper()
	hexBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		t.Fatalf("Failed to decode hex string: %v", err)
	}
	msg, err := pbkdf.NewParamRequestMessageFromBytes(hexBytes)
	if err != nil {
		t.Fatalf("Failed to parse ParamRequestMessage: %v", err)
	}
	return msg
}

func decodeHexdumpPBKDFParamResponseMessage(t *testing.T, hexStr string) pbkdf.ParamResponseMessage {
	t.Helper()
	hexBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		t.Fatalf("Failed to decode hex string: %v", err)
	}
	msg, err := pbkdf.NewParamResponseMessageFromBytes(hexBytes)
	if err != nil {
		t.Fatalf("Failed to parse ParamResponseMessage: %v", err)
	}
	return msg
}

func validatePBKDFParamRequest(msg message.Message) error {
	if msg.SessionID() != 0x0000 {
		return fmt.Errorf("expected SessionID 0x0000, got 0x%04X", msg.SessionID())
	}
	if msg.SecurityFlags().SessionType() != 0x00 {
		return fmt.Errorf("expected SessionType 0x00, got 0x%02X", msg.SecurityFlags().SessionType())
	}
	if !msg.Flags().HasSourceNodeID() {
		return fmt.Errorf("expected SourceNodeID flag to be set")
	}
	sourceNodeID, ok := msg.SourceNodeID()
	if !ok || !sourceNodeID.IsOperational() {
		return fmt.Errorf("expected SourceNodeID to be operational, got %v", sourceNodeID)
	}
	if _, ok := msg.DestinationNodeID(); ok {
		return fmt.Errorf("expected DestinationNodeID flag to be unset")
	}
	if msg.Opcode() != message.PBKDFParamRequest {
		return fmt.Errorf("expected OpCode 0x%02X, got 0x%02X", message.PBKDFParamRequest, msg.Opcode())
	}
	if msg.ProtocolID() != message.SecureChannel {
		return fmt.Errorf("expected ProtocolID 0x%04X, got 0x%04X", message.SecureChannel, msg.ProtocolID())
	}
	if !msg.ExchangeFlags().IsInitiator() {
		return fmt.Errorf("expected ExchangeFlags Initiator to be set")
	}
	if !msg.ExchangeFlags().IsReliability() {
		return fmt.Errorf("expected ExchangeFlags Reliability to be set")
	}
	exID := msg.ExchangeID()
	if exID == 0 {
		return fmt.Errorf("expected random ExchangeID, got 0x%04X", exID)
	}
	return nil
}

func validatePBKDFParamResponse(msg message.Message) error {
	if msg.SessionID() != 0x0000 {
		return fmt.Errorf("expected SessionID 0x0000, got 0x%04X", msg.SessionID())
	}
	if msg.SecurityFlags().SessionType() != 0x00 {
		return fmt.Errorf("expected SessionType 0x00, got 0x%02X", msg.SecurityFlags().SessionType())
	}
	if msg.Flags().HasSourceNodeID() {
		return fmt.Errorf("expected SourceNodeID flag to be unset")
	}
	if _, ok := msg.DestinationNodeID(); !ok {
		return fmt.Errorf("expected DestinationNodeID flag to be set")
	}
	return nil
}
