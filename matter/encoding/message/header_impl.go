// Copyright (C) 2026 The go-matter Authors. All rights reserved.
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

package message

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

type header struct {
	flags          uint8
	sessionID      uint16
	securityFlags  uint8
	messageCounter uint32
	sourceNodeID   uint64
	destNodeID     uint64
}

// HeaderOption configures a Header instance.
type HeaderOption func(*header)

// NewHeader creates a new Header instance with the provided options.
func NewHeader(opts ...HeaderOption) Header {
	h := &header{}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// WithHeaderFlags sets the header flags.
func WithHeaderFlags(flags uint8) HeaderOption {
	return func(h *header) {
		h.flags = flags
	}
}

// WithHeaderSessionID sets the session ID.
func WithHeaderSessionID(sessionID uint16) HeaderOption {
	return func(h *header) {
		h.sessionID = sessionID
	}
}

// WithHeaderSecurityFlags sets the security flags.
func WithHeaderSecurityFlags(flags uint8) HeaderOption {
	return func(h *header) {
		h.securityFlags = flags
	}
}

// WithHeaderMessageCounter sets the message counter.
func WithHeaderMessageCounter(counter uint32) HeaderOption {
	return func(h *header) {
		h.messageCounter = counter
	}
}

// WithHeaderSourceNodeID sets the source node ID.
func WithHeaderSourceNodeID(nodeID uint64) HeaderOption {
	return func(h *header) {
		h.sourceNodeID = nodeID
	}
}

// WithHeaderDestNodeID sets the destination node ID.
func WithHeaderDestNodeID(nodeID uint64) HeaderOption {
	return func(h *header) {
		h.destNodeID = nodeID
	}
}

func (h *header) Flags() uint8 {
	return h.flags
}

func (h *header) SessionID() uint16 {
	return h.sessionID
}

func (h *header) SecurityFlags() uint8 {
	return h.securityFlags
}

func (h *header) MessageCounter() uint32 {
	return h.messageCounter
}

func (h *header) SourceNodeID() uint64 {
	return h.sourceNodeID
}

func (h *header) DestNodeID() uint64 {
	return h.destNodeID
}

func (h *header) Version() uint8 {
	return h.flags & VersionMask
}

func (h *header) HasSourceNodeID() bool {
	return (h.flags & FlagSourceNodeIDPresent) != 0
}

func (h *header) HasDestNodeID() bool {
	return (h.flags & FlagDestNodeIDPresent) != 0
}

func (h *header) Encode() []byte {
	size := 8
	if h.HasSourceNodeID() {
		size += 8
	}
	if h.HasDestNodeID() {
		size += 8
	}

	buf := make([]byte, size)
	buf[0] = h.flags
	binary.LittleEndian.PutUint16(buf[1:3], h.sessionID)
	buf[3] = h.securityFlags
	binary.LittleEndian.PutUint32(buf[4:8], h.messageCounter)

	offset := 8
	if h.HasSourceNodeID() {
		binary.LittleEndian.PutUint64(buf[offset:offset+8], h.sourceNodeID)
		offset += 8
	}
	if h.HasDestNodeID() {
		binary.LittleEndian.PutUint64(buf[offset:offset+8], h.destNodeID)
	}

	return buf
}

// DecodeHeader parses a message frame header from bytes (little-endian).
// Returns the header and the number of bytes consumed, or an error.
func DecodeHeader(data []byte) (Header, int, error) {
	if len(data) < 8 {
		return nil, 0, fmt.Errorf("header too short: need at least 8 bytes, got %d", len(data))
	}

	h := &header{
		flags:          data[0],
		sessionID:      binary.LittleEndian.Uint16(data[1:3]),
		securityFlags:  data[3],
		messageCounter: binary.LittleEndian.Uint32(data[4:8]),
	}

	offset := 8

	if h.HasSourceNodeID() {
		if len(data) < offset+8 {
			return nil, 0, fmt.Errorf("header truncated: source node ID expected but only %d bytes remain", len(data)-offset)
		}
		h.sourceNodeID = binary.LittleEndian.Uint64(data[offset : offset+8])
		offset += 8
	}

	if h.HasDestNodeID() {
		if len(data) < offset+8 {
			return nil, 0, fmt.Errorf("header truncated: dest node ID expected but only %d bytes remain", len(data)-offset)
		}
		h.destNodeID = binary.LittleEndian.Uint64(data[offset : offset+8])
		offset += 8
	}

	return h, offset, nil
}

func (h *header) String() string {
	encoded := h.Encode()
	return fmt.Sprintf("FrameHeader{Version=%d, SessionID=0x%04X, SecurityFlags=0x%02X, MsgCtr=%d, SrcNode=0x%016X (present=%v), DstNode=0x%016X (present=%v)} [%d bytes: %s]",
		h.Version(), h.sessionID, h.securityFlags, h.messageCounter,
		h.sourceNodeID, h.HasSourceNodeID(),
		h.destNodeID, h.HasDestNodeID(),
		len(encoded), hex.EncodeToString(encoded))
}
