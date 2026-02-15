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
	"github.com/cybergarage/go-matter/matter/crypto/pbkdf"
	"github.com/cybergarage/go-matter/matter/io"
)

// Transport represents a PASE transport.
type Transport = io.Transport

type Result struct {
	I2RKey []byte
	R2IKey []byte
	// TODO: add sessionID, etc.
}

// Client represents a PASE client.
type Client struct {
	t        Transport
	passcode Passcode
}

// NewClient returns a new PASE client with the given passcode.
func NewClient(t Transport, passcode Passcode) *Client {
	return &Client{
		t:        t,
		passcode: passcode,
	}
}

// EstablishSession establishes a PASE session.
func (c *Client) EstablishSession(ctx context.Context) (*Result, error) {
	// 1) PBKDFParamRequest
	reqTLV, err := pbkdf.NewParamRequest().Bytes()
	if err != nil {
		return nil, err
	}
	reqBytes := append([]byte{opPBKDFParamRequest}, reqTLV...)
	log.Info("PBKDFParamRequest:")
	log.HexInfo(reqBytes)
	if err := c.t.Transmit(ctx, reqBytes); err != nil {
		log.Errorf("Failed to transmit PBKDFParamRequest: %v", err)
		return nil, err
	}

	// 2) PBKDFParamResponse
	resBytes, err := c.t.Receive(ctx)
	if err != nil {
		log.Errorf("Failed to receive PBKDFParamResponse: %v", err)
		return nil, err
	}
	log.Info("PBKDFParamResponse:")
	log.HexInfo(resBytes)

	if len(resBytes) < 1 || resBytes[0] != opPBKDFParamResponse {
		return nil, fmt.Errorf("unexpected opcode: %v", resBytes)
	}
	pbkdfRes, err := pbkdf.NewParamResponseFromBytes(resBytes[1:])
	if err != nil {
		log.Errorf("Failed to decode PBKDFParamResponse: %v", err)
		return nil, err
	}

	// 3) SPAKE2+ (PASE)
	hs := NewHandshake(HandshakeRoleClient, HandshakeOptions{
		Passcode:  c.passcode.Bytes(),
		Salt:      pbkdfRes.Salt(),
		PBKDFIter: int(pbkdfRes.Iterations()),
		Hash:      nil, // TODO: support different hash algorithms
	})

	// 3-1) Pake1
	x, err := hs.Start() // TODO: spake2p.Start(), not implemented yet
	if err != nil {
		return nil, err
	}
	if err := c.t.Transmit(ctx, NewPake1(x).Bytes()); err != nil {
		log.Errorf("Failed to transmit Pake1: %v", err)
		return nil, err
	}

	// 3-2) Pake2
	p2raw, err := c.t.Receive(ctx)
	if err != nil {
		log.Errorf("Failed to receive Pake2: %v", err)
		return nil, err
	}
	// TODO: decode p2raw
	_ = p2raw

	return nil, fmt.Errorf("PASE client flow is incomplete: requires spake2p + message parsing")
}
