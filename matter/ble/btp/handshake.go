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

package btp

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/cybergarage/go-matter/matter/errors"
)

// HandshakeRequest represents a BTP handshake request.
type HandshakeRequest interface {
	// Versiond returns the BTP version.
	Versiond() int
	// Bytes returns the byte representation of the handshake request.
	Bytes() []byte
	// String returns the string representation of the handshake request.
	String() string
}

type handshakeRequest struct {
	bytes []byte
}

// NewHandshakeRequest returns a new HandshakeRequest.
func NewHandshakeRequest() HandshakeRequest {
	// Construct handshake request frame (9 bytes)[6]
	handshake := make([]byte, 9)
	handshake[0] = 0x65 // Control flags: Handshake + Management + etc. (0x65)[7]
	handshake[1] = 0x6C // Management Opcode: 0x6C (BLE transport handshake)
	handshake[2] = 0x04 // BTP version = 4
	// Bytes [3..7]: supported BTP version mask or reserved (set to 0)
	for i := 3; i <= 7; i++ {
		handshake[i] = 0x00
	}
	handshake[8] = computeCRC8(handshake[:8]) // CRC8 over first 8 bytes
	return &handshakeRequest{
		bytes: handshake,
	}
}

// Versiond returns the BTP version.
func (req *handshakeRequest) Versiond() int {
	return int(req.bytes[2])
}

// Bytes returns the byte representation of the handshake request.
func (req *handshakeRequest) Bytes() []byte {
	return req.bytes
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

// NewHandshakeResponseFromBytes returns a new HandshakeResponse from the specified bytes.
func NewHandshakeResponseFromBytes(data []byte) (HandshakeResponse, error) {
	// 4.19.3.2. BTP Handshake Response
	if len(data) < 6 {
		return nil, fmt.Errorf("%w: %s", errors.ErrInvalid, "handshake response length is less than 3")
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
