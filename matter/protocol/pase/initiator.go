// Copyright (C) 2025 The go-matter Authors. All rights reserved.
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

package pase

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter/crypto"
	"github.com/cybergarage/go-matter/matter/encoding/message"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	"github.com/cybergarage/go-matter/matter/io"
	"github.com/cybergarage/go-matter/matter/protocol/pase/pake"
	"github.com/cybergarage/go-matter/matter/protocol/pase/pbkdf"
)

// Transport represents a PASE transport.
type Transport = io.Transport

// ErrPASEVerification is returned when PASE verification fails (e.g., cB mismatch).
var ErrPASEVerification = errors.New("PASE verification failed")

// ErrStatusReport is returned when the device responds with a non-success StatusReport.
var ErrStatusReport = errors.New("StatusReport indicates failure")

// CryptoSymmetricKeyLen is the length of the AES-CCM session key (128 bits).
// 3.5. Public Key Cryptography.
const CryptoSymmetricKeyLen = 16

// Initiator represents a PASE client.
type Initiator struct {
	t        Transport
	passcode Passcode
}

// NewInitiator returns a new PASE initiator with the given passcode.
func NewInitiator(t Transport, passcode Passcode) *Initiator {
	return &Initiator{
		t:        t,
		passcode: passcode,
	}
}

// receiveSkipAck receives a message from the transport, silently discarding any
// MRP standalone ACK frames (opcode 0x10) until a non-ACK message arrives.
func (i *Initiator) receiveSkipAck(ctx context.Context) ([]byte, error) {
	for {
		b, err := i.t.Receive(ctx)
		if err != nil {
			return nil, err
		}
		msg, err := message.NewMessageFromBytes(b)
		if err != nil {
			return nil, fmt.Errorf("failed to parse received message: %w", err)
		}
		if msg.Opcode().IsMRPStandaloneAck() {
			log.Debugf("received standalone MRP ACK, waiting for next message")
			continue
		}
		return b, nil
	}
}

// EstablishSession establishes a PASE session.
// 4.14.1. PASE – Password-Authenticated Session Establishment.
func (i *Initiator) EstablishSession(ctx context.Context) (SessionKeys, error) {
	// 1) PBKDFParamRequest
	paramReqMsg, err := pbkdf.NewParamRequestMessage()
	if err != nil {
		return nil, err
	}
	reqBytes, err := paramReqMsg.Bytes()
	if err != nil {
		return nil, err
	}
	log.Infof("PBKDFParamRequest: %s", paramReqMsg.String())
	log.HexInfo(reqBytes)
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ts := pbkdf.DefaultSessionActiveThreshold
		if sessionParams, ok := paramReqMsg.InitiatorSessionParams(); ok {
			if at, ok := sessionParams.SessionActiveThreshold(); ok {
				ts = at
			}
		}
		ctx, cancel = context.WithTimeout(ctx, ts)
		defer cancel()
	}
	if err := i.t.Transmit(ctx, reqBytes); err != nil {
		log.Errorf("Failed to transmit PBKDFParamRequest: %v", err)
		return nil, err
	}

	// 2) PBKDFParamResponse (skip any standalone ACK for the request)
	resBytes, err := i.receiveSkipAck(ctx)
	if err != nil {
		log.Errorf("Failed to receive PBKDFParamResponse: %v", err)
		return nil, err
	}
	pbkdfResMsg, err := pbkdf.NewParamResponseMessageFromBytes(resBytes)
	if err != nil {
		log.Errorf("Failed to decode PBKDFParamResponse: %v", err)
		return nil, err
	}
	log.Infof("PBKDFParamResponse: %s", pbkdfResMsg.String())
	log.HexInfo(resBytes)

	// 3) Derive SPAKE2+ initiator values from the received PBKDF parameters.
	// 3.10. Password-Authenticated Key Exchange (PAKE).
	salt, ok := pbkdfResMsg.PBKDFParams().Salt()
	if !ok {
		return nil, fmt.Errorf("PBKDFParamResponse missing salt")
	}
	iterations, ok := pbkdfResMsg.PBKDFParams().Iterations()
	if !ok {
		return nil, fmt.Errorf("PBKDFParamResponse missing iterations")
	}
	passcodeBytes := i.passcode.Bytes()
	w0, w1, err := crypto.CryptoPAKEValuesInitiator(passcodeBytes, salt, iterations)
	if err != nil {
		return nil, fmt.Errorf("CryptoPAKEValuesInitiator: %w", err)
	}
	// Generate ephemeral scalar x and compute pA = x·P + w0·M.
	x, err := crypto.CryptoPAKERandomScalar()
	if err != nil {
		return nil, fmt.Errorf("CryptoPAKERandomScalar: %w", err)
	}
	pA, err := crypto.CryptoPA(x, w0)
	if err != nil {
		return nil, fmt.Errorf("CryptoPA: %w", err)
	}

	// 4) Pake1: send pA to the responder.
	pake1Msg, err := pake.NewPake1Message(
		pake.WithPake1MessageParamRequestMessage(paramReqMsg),
		pake.WithPake1MessageParamResponseMessage(pbkdfResMsg),
		pake.WithPake1PA(pA),
	)
	if err != nil {
		return nil, err
	}
	pake1Bytes, err := pake1Msg.Bytes()
	if err != nil {
		return nil, err
	}
	log.Infof("Pake1: %s", pake1Msg.String())
	log.HexInfo(pake1Bytes)
	if err := i.t.Transmit(ctx, pake1Bytes); err != nil {
		log.Errorf("Failed to transmit Pake1: %v", err)
		return nil, err
	}

	// 5) Pake2: receive pB and cB from the responder (skip any standalone ACK).
	pake2Bytes, err := i.receiveSkipAck(ctx)
	if err != nil {
		log.Errorf("Failed to receive Pake2: %v", err)
		return nil, err
	}
	pake2Msg, err := pake.NewPake2MessageFromBytes(pake2Bytes)
	if err != nil {
		log.Errorf("Failed to decode Pake2: %v", err)
		return nil, err
	}
	log.Infof("Pake2: %s", pake2Msg.String())
	log.HexInfo(pake2Bytes)

	// 6) Compute shared points Z and V, then the transcript TT.
	// 3.10.3. Computation of transcript TT.
	pB := pake2Msg.PB()
	cBReceived := pake2Msg.CB()
	Z, V, err := crypto.CryptoPAKESharedPoints(x, w0, w1, pB)
	if err != nil {
		return nil, fmt.Errorf("CryptoPAKESharedPoints: %w", err)
	}
	tt, err := crypto.CryptoTranscript(
		paramReqMsg.Payload(),
		pbkdfResMsg.Payload(),
		pA, pB, Z, V, w0,
	)
	if err != nil {
		return nil, fmt.Errorf("CryptoTranscript: %w", err)
	}

	// 7) Derive cA, cB, and Ke from TT.
	// 3.10.4. Computation of cA, cB and Ke.
	cA, cBExpected, Ke, err := crypto.CryptoP2(tt, pA, pB)
	if err != nil {
		return nil, fmt.Errorf("CryptoP2: %w", err)
	}

	// 8) Verify cB: the received cB must match our expected cB using constant-time comparison.
	if subtle.ConstantTimeCompare(cBReceived, cBExpected) != 1 {
		return nil, fmt.Errorf("%w: cB mismatch", ErrPASEVerification)
	}

	// 9) Pake3: send cA to the responder to complete authentication.
	pake3Msg, err := pake.NewPake3Message(
		pake.WithPake3MessageParamRequestMessage(paramReqMsg),
		pake.WithPake3MessagePake1Message(pake1Msg),
		pake.WithPake3MessagePake2Message(pake2Msg),
		pake.WithPake3MessagePrecomputedCA(cA),
	)
	if err != nil {
		return nil, err
	}
	pake3Bytes, err := pake3Msg.Bytes()
	if err != nil {
		return nil, err
	}
	log.Infof("Pake3: %s", pake3Msg.String())
	log.HexInfo(pake3Bytes)
	if err := i.t.Transmit(ctx, pake3Bytes); err != nil {
		log.Errorf("Failed to transmit Pake3: %v", err)
		return nil, err
	}

	// 10) StatusReport: receive the final status from the responder.
	// 4.14.1.2. Protocol Details.
	statusBytes, err := i.receiveSkipAck(ctx)
	if err != nil {
		log.Errorf("Failed to receive StatusReport: %v", err)
		return nil, err
	}
	if err := i.parseStatusReport(statusBytes); err != nil {
		return nil, err
	}

	// 11) Derive session keys from Ke via HKDF.
	// 4.14.1.3. Key Derivation.
	// I2RKey || R2IKey || AttestationChallenge =
	//   Crypto_KDF(inputKey := Ke, salt := null, info := "SessionKeys", len := 3*128 bits)
	sessionKeys, err := crypto.CryptoHKDF(Ke, nil, []byte("SessionKeys"), 3*CryptoSymmetricKeyLen)
	if err != nil {
		return nil, fmt.Errorf("session key derivation: %w", err)
	}

	// Copy each key into an independent slice to prevent memory aliasing.
	i2rKey := make([]byte, CryptoSymmetricKeyLen)
	r2iKey := make([]byte, CryptoSymmetricKeyLen)
	attestationChallenge := make([]byte, CryptoSymmetricKeyLen)
	copy(i2rKey, sessionKeys[0:CryptoSymmetricKeyLen])
	copy(r2iKey, sessionKeys[CryptoSymmetricKeyLen:2*CryptoSymmetricKeyLen])
	copy(attestationChallenge, sessionKeys[2*CryptoSymmetricKeyLen:3*CryptoSymmetricKeyLen])

	return newSessionKeys(i2rKey, r2iKey, attestationChallenge), nil
}

// parseStatusReport parses a received StatusReport message and returns an error if PASE failed.
// 2.11.2. Status Report TLV format.
func (i *Initiator) parseStatusReport(data []byte) error {
	msg, err := message.NewMessageFromBytes(data)
	if err != nil {
		return fmt.Errorf("failed to parse StatusReport message: %w", err)
	}
	if !msg.Opcode().IsStatusReport() {
		return fmt.Errorf("expected StatusReport (0x40), got opcode 0x%02x", uint8(msg.Opcode()))
	}

	// Parse TLV payload: { GeneralCode [0], ProtocolId [1], ProtocolCode [2] }
	dec := tlv.NewDecoderWithBytes(msg.Payload())
	if !dec.Next() {
		return fmt.Errorf("StatusReport: empty payload")
	}
	elem := dec.Element()
	if !elem.Type().IsStructure() {
		return fmt.Errorf("StatusReport: expected structure, got %v", elem.Type())
	}
	var generalCode uint16
	var protocolCode uint16
	for dec.Next() {
		elem = dec.Element()
		if elem.Type().IsEndOfContainer() {
			break
		}
		ct, ok := elem.Tag().(tlv.ContextTag)
		if !ok {
			continue
		}
		switch ct.ContextNumber() {
		case 0:
			v, ok := elem.Unsigned2()
			if ok {
				generalCode = v
			}
		case 2:
			v, ok := elem.Unsigned2()
			if ok {
				protocolCode = v
			}
		}
	}
	if generalCode != 0 {
		return fmt.Errorf("%w: GeneralCode=%d ProtocolCode=%d", ErrStatusReport, generalCode, protocolCode)
	}
	log.Infof("PASE StatusReport: success (GeneralCode=0, ProtocolCode=%d)", protocolCode)
	return nil
}
