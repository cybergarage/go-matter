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
	paramReqMsg, err := NewPBKDBParamRequestMessage()
	if err != nil {
		return nil, err
	}
	reqBytes := paramReqMsg.Bytes()
	log.Info("PBKDFParamRequest:")
	log.HexInfo(reqBytes)
	if err := i.t.Transmit(ctx, reqBytes); err != nil {
		log.Errorf("Failed to transmit PBKDFParamRequest: %v", err)
		return nil, err
	}

	// 2) PBKDFParamResponse
	resBytes, err := i.t.Receive(ctx)
	if err != nil {
		log.Errorf("Failed to receive PBKDFParamResponse: %v", err)
		return nil, err
	}
	log.Info("PBKDFParamResponse:")
	log.HexInfo(resBytes)

	pbkdfRes, err := pbkdf.NewParamResponseFromBytes(resBytes[1:])
	if err != nil {
		log.Errorf("Failed to decode PBKDFParamResponse: %v", err)
		return nil, err
	}

	// 3) SPAKE2+ (PASE)
	salt, ok := pbkdfRes.PBKDFParams().Salt()
	if !ok {
		return nil, fmt.Errorf("PBKDF parameters missing salt")
	}
	iter, ok := pbkdfRes.PBKDFParams().Iterations()
	if !ok {
		return nil, fmt.Errorf("PBKDF parameters missing iterations")
	}
	hs, err := NewHandshake(HandshakeRoleClient, HandshakeOptions{
		Passcode:  i.passcode.Bytes(),
		Salt:      salt,
		PBKDFIter: iter,
		Hash:      nil, // TODO: support different hash algorithms
	})
	if err != nil {
		return nil, err
	}

	// 3-1) Pake1
	_, err = hs.Start() // TODO: spake2p.Start(), not implemented yet
	if err != nil {
		return nil, err
	}
	pake1 := pake.NewPake1()
	pake1Bytes, err := pake1.Bytes()
	if err != nil {
		return nil, err
	}
	if err := i.t.Transmit(ctx, pake1Bytes); err != nil {
		log.Errorf("Failed to transmit Pake1: %v", err)
		return nil, err
	}

	// 3-2) Pake2
	p2raw, err := i.t.Receive(ctx)
	if err != nil {
		log.Errorf("Failed to receive Pake2: %v", err)
		return nil, err
	}
	// TODO: decode p2raw
	_ = p2raw

	return nil, fmt.Errorf("PASE client flow is incomplete: requires spake2p + message parsing")
}
