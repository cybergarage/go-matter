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

package ble

import (
	"encoding/hex"
	"fmt"
	"strings"
)

var (
	// 4.19.3.1. BTP Handshake Request.
	handshakeReqestPayload = []byte{0x65, 0x6C, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 244}
)

// HandshakeRequest represents a BTP handshake request.
type HandshakeRequest interface {
	// Bytes returns the byte representation of the handshake request.
	Bytes() []byte
	// String returns the string representation of the handshake request.
	String() string
}

type handshakeRequest struct {
}

func newHandshakeRequest() HandshakeRequest {
	return &handshakeRequest{}
}

func (req *handshakeRequest) Bytes() []byte {
	return handshakeReqestPayload
}

// String returns the string representation of the handshake request.
func (req *handshakeRequest) String() string {
	return strings.ToUpper(hex.EncodeToString(req.Bytes()))
}

// HandshakeResponse represents a BTP handshake response.
type HandshakeResponse interface {
	// Bytes returns the byte representation of the handshake response.
	Bytes() []byte
	// String returns the string representation of the handshake response.
	String() string
}

type handshakeResponse struct {
	bytes []byte
}

func newHandshakeResponse(data []byte) (HandshakeResponse, error) {
	// 4.19.3.2. BTP Handshake Response
	if len(data) < 6 {
		return nil, fmt.Errorf("%w: %s", ErrInvalid, "handshake response length is less than 3")
	}
	return &handshakeResponse{
		bytes: data,
	}, nil
}

// Bytes returns the byte representation of the handshake response.
func (res *handshakeResponse) Bytes() []byte {
	return res.bytes
}

// String returns the string representation of the handshake response.
func (res *handshakeResponse) String() string {
	return strings.ToUpper(hex.EncodeToString(res.Bytes()))
}
