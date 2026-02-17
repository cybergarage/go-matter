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
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/cybergarage/go-matter/matter/types"
)

const (
	minHeaderSize = 8
)

type header struct {
	flags         Flag
	sessionID     uint16
	securityFlags SecurityFlag
	msgCounter    uint32
	srcNodeID     uint64
	destNodeID    uint64
}

// HeaderOption configures a Header instance.
type HeaderOption func(*header)

// WithHeaderFlags sets the header flags.
func WithHeaderFlags(flags Flag) HeaderOption {
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
func WithHeaderSecurityFlags(flags SecurityFlag) HeaderOption {
	return func(h *header) {
		h.securityFlags = flags
	}
}

// WithHeaderMessageCounter sets the message counter.
func WithHeaderMessageCounter(counter uint32) HeaderOption {
	return func(h *header) {
		h.msgCounter = counter
	}
}

// WithHeaderSourceNodeID sets the source node ID.
func WithHeaderSourceNodeID(nodeID NodeID) HeaderOption {
	return func(h *header) {
		h.flags |= SourceNodeIDPresentMask
		h.srcNodeID = uint64(nodeID)
	}
}

// WithHeaderDestinationNodeID sets the destination node ID.
func WithHeaderDestinationNodeID(nodeID NodeID) HeaderOption {
	return func(h *header) {
		h.flags |= DestinationNodeIDPresent
		h.destNodeID = uint64(nodeID)
	}
}

// WithHeaderGroupID sets the group ID, which is encoded in the destination node ID field with the destination node ID presence flag.
func WithHeaderGroupID(groupID GroupID) HeaderOption {
	return func(h *header) {
		h.flags |= GroupIDPresent
		h.destNodeID = uint64(groupID)
	}
}

// NewHeader creates a new Header instance with the provided options.
func NewHeader(opts ...HeaderOption) Header {
	h := &header{
		flags:         0x00,
		sessionID:     0x0000,
		securityFlags: 0x00,
		msgCounter:    0,
		srcNodeID:     0,
		destNodeID:    0,
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// NewHeaderFromBytes reads a header from the provided byte slice.
// Returns the header and the number of bytes consumed, or an error.
func NewHeaderFromBytes(data []byte) (Header, error) {
	return NewHeaderFromReader(bytes.NewReader(data))
}

// NewHeaderFromReader reads a header from an io.Reader without using io.ReadFull or NewHeaderFromBytes.
func NewHeaderFromReader(reader io.Reader) (Header, error) {
	var buf [8]byte
	_, err := io.ReadAtLeast(reader, buf[:], minHeaderSize)
	if err != nil {
		return nil, err
	}

	h := &header{
		flags:         Flag(buf[0]),
		sessionID:     binary.LittleEndian.Uint16(buf[1:3]),
		securityFlags: SecurityFlag(buf[3]),
		msgCounter:    binary.LittleEndian.Uint32(buf[4:8]),
		srcNodeID:     0,
		destNodeID:    0,
	}

	// Optional SourceNodeID
	if h.flags.HasSourceNodeIDField() {
		extra := make([]byte, 8)
		_, err := io.ReadAtLeast(reader, extra, 8)
		if err != nil {
			return nil, err
		}
		h.srcNodeID = binary.LittleEndian.Uint64(extra)
	}
	// Optional DestinationNodeID
	if h.flags.HasDestinationNodeIDField() {
		extra := make([]byte, 8)
		_, err := io.ReadAtLeast(reader, extra, 8)
		if err != nil {
			return nil, err
		}
		h.destNodeID = binary.LittleEndian.Uint64(extra)
	}

	return h, nil
}

func (h *header) Version() uint8 {
	return h.flags.Version()
}

func (h *header) Flags() Flag {
	return h.flags
}

func (h *header) SessionID() uint16 {
	return h.sessionID
}

func (h *header) SecurityFlags() SecurityFlag {
	return h.securityFlags
}

func (h *header) MessageCounter() uint32 {
	return h.msgCounter
}

func (h *header) SourceNodeID() (NodeID, bool) {
	return NodeID(h.srcNodeID), h.flags.HasSourceNodeIDField()
}

func (h *header) DestinationNodeID() (NodeID, bool) {
	return NodeID(h.destNodeID), h.flags.HasDestinationNodeIDField()
}

func (h *header) GroupID() (GroupID, bool) {
	if !h.flags.HasDestinationNodeIDField() {
		return GroupID(0), false
	}
	groupID, err := types.NewGroupIDFrom(h.destNodeID)
	if err != nil {
		return GroupID(0), false
	}
	return groupID, true
}

func (h *header) Bytes() []byte {
	size := minHeaderSize
	if h.flags.HasSourceNodeIDField() {
		size += 8
	}
	if h.flags.HasDestinationNodeIDField() {
		size += 8
	}

	buf := make([]byte, size)
	buf[0] = byte(h.flags)
	binary.LittleEndian.PutUint16(buf[1:3], h.sessionID)
	buf[3] = byte(h.securityFlags)
	binary.LittleEndian.PutUint32(buf[4:8], h.msgCounter)

	offset := minHeaderSize
	if h.flags.HasSourceNodeIDField() {
		binary.LittleEndian.PutUint64(buf[offset:offset+8], h.srcNodeID)
		offset += 8
	}
	if h.flags.HasDestinationNodeIDField() {
		binary.LittleEndian.PutUint64(buf[offset:offset+8], h.destNodeID)
	}

	return buf
}

// String returns a human-readable string representation of the header for debugging purposes.
func (h *header) String() string {
	encoded := h.Bytes()
	return fmt.Sprintf("MessageHeader{Version=%d, SessionID=0x%04X, %s, MsgCtr=%d, SrcNode=0x%016X (present=%v), DstNode=0x%016X (present=%v)} [%d bytes: %s]",
		h.Version(), h.sessionID, h.securityFlags.String(), h.msgCounter,
		h.srcNodeID, h.flags.HasSourceNodeIDField(),
		h.destNodeID, h.flags.HasDestinationNodeIDField(),
		len(encoded), hex.EncodeToString(encoded))
}
