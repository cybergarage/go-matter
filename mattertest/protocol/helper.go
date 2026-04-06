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
	"github.com/cybergarage/go-matter/matter/protocol/mrp"
	"github.com/cybergarage/go-matter/matter/protocol/pase/pake"
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

func decodeHexdumpMRPAck(t *testing.T, hexStr string) mrp.Ack {
	t.Helper()
	hexBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		t.Fatalf("Failed to decode hex string: %v", err)
	}
	msg, err := mrp.NewAckFromBytes(hexBytes)
	if err != nil {
		t.Fatalf("Failed to parse Ack: %v", err)
	}
	return msg
}

func decodeHexdumpPake1Message(t *testing.T, hexStr string) pake.Pake1Message {
	t.Helper()
	hexBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		t.Fatalf("Failed to decode hex string: %v", err)
	}
	msg, err := pake.NewPake1MessageFromBytes(hexBytes)
	if err != nil {
		t.Fatalf("Failed to parse Pake1Message: %v", err)
	}
	return msg
}

func decodeHexdumpPake2Message(t *testing.T, hexStr string) pake.Pake2Message {
	t.Helper()
	hexBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		t.Fatalf("Failed to decode hex string: %v", err)
	}
	msg, err := pake.NewPake2MessageFromBytes(hexBytes)
	if err != nil {
		t.Fatalf("Failed to parse Pake2Message: %v", err)
	}
	return msg
}

func decodeHexdumpPake3Message(t *testing.T, hexStr string) pake.Pake3Message {
	t.Helper()
	hexBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		t.Fatalf("Failed to decode hex string: %v", err)
	}
	msg, err := pake.NewPake3MessageFromBytes(hexBytes)
	if err != nil {
		t.Fatalf("Failed to parse Pake3Message: %v", err)
	}
	return msg
}

func validatePBKDFParamRequest(msg pbkdf.ParamRequestMessage) error {
	// 4.14.1.2. Protocol Details

	if !msg.ProtocolID().IsSecureChannel() {
		return fmt.Errorf("expected ProtocolID to be SecureChannel, got 0x%04X", msg.ProtocolID())
	}
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

	// 4.14.1.2. Protocol Details
	// pbkdfparamreq-struct => STRUCTURE [ tag-order ]
	// {
	//   initiatorRandom [1] : OCTET STRING [ length 32 ],
	//   initiatorSessionId [2] : UNSIGNED INTEGER [ range 16-bits ],
	//   passcodeId [3] : UNSIGNED INTEGER [ length 16-bits ],
	//   HasPBKDFParams [4] : BOOLEAN,
	//   initiatorSessionParams [5, optional] : session-parameter-struct
	// }

	if len(msg.InitiatorRandom()) != pbkdf.InitiatorRandomLength {
		return fmt.Errorf("expected InitiatorRandom length %d, got %d", pbkdf.InitiatorRandomLength, len(msg.InitiatorRandom()))
	}
	if msg.PasscodeID() != 0 {
		return fmt.Errorf("expected PasscodeID 0, got %d", msg.PasscodeID())
	}
	if msg.HasPBKDFParams() {
		return fmt.Errorf("expected PBKDFParams flag to be unset")
	}
	return nil
}

func validatePBKDFParamResponse(msg pbkdf.ParamResponseMessage) error {
	// 4.14.1.2. Protocol Details

	if !msg.ProtocolID().IsSecureChannel() {
		return fmt.Errorf("expected ProtocolID to be SecureChannel, got 0x%04X", msg.ProtocolID())
	}
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
	if !msg.ExchangeFlags().IsAck() {
		return fmt.Errorf("expected ExchangeFlags Acknowledgement to be set")
	}
	if !msg.ExchangeFlags().IsReliability() {
		return fmt.Errorf("expected ExchangeFlags Reliability to be set")
	}

	// 4.14.1.2. Protocol Details
	// pbkdfparamresp-struct => STRUCTURE [ tag-order ]
	// {
	//   initiatorRandom [1] : OCTET STRING [ length 32 ],
	//   responderRandom [2] : OCTET STRING [ length 32 ],
	//   responderSessionId [3] : UNSIGNED INTEGER [ range 16-bits ],
	//   pbkdf_parameters [4] : Crypto_PBKDFParameterSet,
	//   responderSessionParams [5, optional] : session-parameter-struct
	// }

	if len(msg.InitiatorRandom()) != pbkdf.InitiatorRandomLength {
		return fmt.Errorf("expected InitiatorRandom length %d, got %d", pbkdf.InitiatorRandomLength, len(msg.InitiatorRandom()))
	}
	if len(msg.ResponderRandom()) != pbkdf.ResponderRandomLength {
		return fmt.Errorf("expected ResponderRandom length %d, got %d", pbkdf.ResponderRandomLength, len(msg.ResponderRandom()))
	}
	if iter, ok := msg.PBKDFParams().Iterations(); !ok || iter < pbkdf.PBKDBFIterationsMin {
		return fmt.Errorf("expected PBKDFParams IterationCount to be at least %d, got %d", pbkdf.PBKDBFIterationsMin, iter)
	}
	if salt, ok := msg.PBKDFParams().Salt(); !ok || len(salt) < pbkdf.PBKDBFSaltMin {
		return fmt.Errorf("expected PBKDFParams to be present")
	}

	return nil
}

func validateAckMessage(msg mrp.Ack) error {
	// 4.12.7.1. MRP Standalone Acknowledgement

	if !msg.ProtocolID().IsSecureChannel() {
		return fmt.Errorf("expected ProtocolID to be SecureChannel, got 0x%04X", msg.ProtocolID())
	}
	if !msg.IsAck() {
		return fmt.Errorf("expected ACK flag to be set")
	}
	if _, ok := msg.AckMessageCounter(); !ok {
		return fmt.Errorf("expected AckMessageCounter to be present")
	}
	if !msg.Opcode().IsMRPStandaloneAck() {
		return fmt.Errorf("expected opcode to be MRPStandaloneAck")
	}
	if msg.IsReliability() {
		return fmt.Errorf("ACK should not have reliability flag set")
	}
	if len(msg.Payload()) != 0 {
		return fmt.Errorf("expected empty payload for standalone ACK, got %d bytes", len(msg.Payload()))
	}

	return nil
}

func validatePake1Message(msg pake.Pake1Message) error {
	if !msg.ExchangeFlags().IsInitiator() {
		return fmt.Errorf("expected ExchangeFlags Initiator to be set")
	}
	if !msg.ExchangeFlags().IsAck() {
		return fmt.Errorf("expected ExchangeFlags Acknowledgement to be set")
	}
	if !msg.ExchangeFlags().IsReliability() {
		return fmt.Errorf("expected ExchangeFlags Reliability to be set")
	}
	return nil
}

func validatePake2Message(msg pake.Pake2Message) error {
	return nil
}

func validatePake3Message(msg pake.Pake3Message) error {
	return nil
}
