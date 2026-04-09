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
	"fmt"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter/io"
	"github.com/cybergarage/go-matter/matter/protocol/mrp"
	"github.com/cybergarage/go-matter/matter/protocol/pase/pake"
	"github.com/cybergarage/go-matter/matter/protocol/pase/pbkdf"
)

// Transport represents a PASE transport.
type Transport = io.Transport

type Result struct {
	I2RKey []byte
	R2IKey []byte
	// TODO: add sessionID, etc.
}

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

// EstablishSession establishes a PASE session.
func (i *Initiator) EstablishSession(ctx context.Context) (*Result, error) {
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

	// 2) PBKDFParamRequest ACK (optional)
	if paramReqMsg.IsReliability() {
		resBytes, err := i.t.Receive(ctx)
		if err != nil {
			log.Errorf("Failed to receive PBKDFParamResponse ACK: %v", err)
			return nil, err
		}
		paramReqMsgAck, err := mrp.NewAckFromBytes(resBytes)
		if err != nil {
			log.Errorf("Failed to decode PBKDFParamResponse ACK: %v", err)
			return nil, err
		}
		log.Infof("PBKDFParamRequest ACK: %s", paramReqMsgAck.String())
		log.HexInfo(resBytes)
	}

	// 2) PBKDFParamResponse
	resBytes, err := i.t.Receive(ctx)
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

	// 3) Pake1
	pake1Params := pbkdf.NewParams(
		pbkdf.WithParamsPasscode(i.passcode),
		pbkdf.WithParamsParamResponse(pbkdfResMsg.PBKDFParams()),
	)
	pake1Msg, err := pake.NewPake1Message(
		pake.WithPake1MessageParamRequestMessage(paramReqMsg),
		pake.WithPake1MessageParamResponseMessage(pbkdfResMsg),
		pake.WithPake1MessagePBKDFParams(pake1Params),
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

	// 3) Pake2 ACK (optional)
	if pake1Msg.IsReliability() {
		resBytes, err := i.t.Receive(ctx)
		if err != nil {
			log.Errorf("Failed to receive Pake2 ACK: %v", err)
			return nil, err
		}
		pake2Ack, err := mrp.NewAckFromBytes(resBytes)
		if err != nil {
			log.Errorf("Failed to decode Pake2 ACK: %v", err)
			return nil, err
		}
		log.Infof("Pake2 ACK: %s", pake2Ack.String())
		log.HexInfo(resBytes)
	}

	// 3) Pake2
	pake2Bytes, err := i.t.Receive(ctx)
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

	// 4) Pake3
	pake3Msg, err := pake.NewPake3Message(
		pake.WithPake3MessageParamRequestMessage(paramReqMsg),
		pake.WithPake3MessageParamResponseMessage(pbkdfResMsg),
		pake.WithPake3MessagePake1Message(pake1Msg),
		pake.WithPake3MessagePake2Message(pake2Msg),
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

	return nil, fmt.Errorf("PASE client flow is incomplete: requires spake2p + message parsing")
}
