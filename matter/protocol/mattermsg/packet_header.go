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

package mattermsg

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// PacketHeader represents the Matter message packet header.
// Reference: Matter Core Spec 1.5, Section 4.7.2 (Message Format)
type PacketHeader struct {
	// Flags contains version and control flags
	Flags uint8
	// SessionID identifies the secure session (0x0000 for unsecured messages)
	SessionID uint16
	// SecurityFlags contains security-related flags
	SecurityFlags uint8
	// MessageCounter is an incrementing counter for message ordering
	MessageCounter uint32
	// SourceNodeID is the sender's node identifier (optional, present when the header indicates a source node ID is included; see HasSourceNodeID)
	SourceNodeID uint64
	// DestNodeID is the destination node identifier (optional, present when the header indicates a destination node ID is included; see HasDestNodeID)
	DestNodeID uint64
}

// PacketHeaderFlags contains flag bit positions for the packet header flags field.
// Reference: Matter Core Spec 1.5, Section 4.7.2
const (
	// VersionMask extracts the version field (bits 0-3)
	VersionMask = 0x0F
	// FlagDestNodeIDPresent indicates destination node ID is present (bit 5)
	FlagDestNodeIDPresent = 0x20
	// FlagSourceNodeIDPresent indicates source node ID is present (bit 6)
	FlagSourceNodeIDPresent = 0x40
	// DSIZ mask (bits 6-7, in second byte for extended format)
	// Note: DSIZ is not used in this minimal implementation
	DSIZMask  = 0xC0
	DSIZShift = 6
)

// Version extracts the protocol version from the flags field.
func (h *PacketHeader) Version() uint8 {
	return h.Flags & VersionMask
}

// HasSourceNodeID returns true if the source node ID is present.
func (h *PacketHeader) HasSourceNodeID() bool {
	return (h.Flags & FlagSourceNodeIDPresent) != 0
}

// HasDestNodeID returns true if the destination node ID is present.
func (h *PacketHeader) HasDestNodeID() bool {
	return (h.Flags & FlagDestNodeIDPresent) != 0
}

// Encode serializes the packet header to bytes (little-endian).
func (h *PacketHeader) Encode() []byte {
	// Minimum header size: flags(1) + sessionID(2) + securityFlags(1) + messageCounter(4) = 8 bytes
	size := 8
	if h.HasSourceNodeID() {
		size += 8
	}
	if h.HasDestNodeID() {
		size += 8
	}

	buf := make([]byte, size)
	buf[0] = h.Flags
	binary.LittleEndian.PutUint16(buf[1:3], h.SessionID)
	buf[3] = h.SecurityFlags
	binary.LittleEndian.PutUint32(buf[4:8], h.MessageCounter)

	offset := 8
	if h.HasSourceNodeID() {
		binary.LittleEndian.PutUint64(buf[offset:offset+8], h.SourceNodeID)
		offset += 8
	}
	if h.HasDestNodeID() {
		binary.LittleEndian.PutUint64(buf[offset:offset+8], h.DestNodeID)
	}

	return buf
}

// Decode parses a packet header from bytes (little-endian).
// Returns the header and the number of bytes consumed, or an error.
func DecodePacketHeader(data []byte) (*PacketHeader, int, error) {
	if len(data) < 8 {
		return nil, 0, fmt.Errorf("packet header too short: need at least 8 bytes, got %d", len(data))
	}

	h := &PacketHeader{
		Flags:          data[0],
		SessionID:      binary.LittleEndian.Uint16(data[1:3]),
		SecurityFlags:  data[3],
		MessageCounter: binary.LittleEndian.Uint32(data[4:8]),
	}

	offset := 8

	if h.HasSourceNodeID() {
		if len(data) < offset+8 {
			return nil, 0, fmt.Errorf("packet header truncated: source node ID expected but only %d bytes remain", len(data)-offset)
		}
		h.SourceNodeID = binary.LittleEndian.Uint64(data[offset : offset+8])
		offset += 8
	}

	if h.HasDestNodeID() {
		if len(data) < offset+8 {
			return nil, 0, fmt.Errorf("packet header truncated: dest node ID expected but only %d bytes remain", len(data)-offset)
		}
		h.DestNodeID = binary.LittleEndian.Uint64(data[offset : offset+8])
		offset += 8
	}

	return h, offset, nil
}

// String returns a human-readable representation with hex dump.
func (h *PacketHeader) String() string {
	encoded := h.Encode()
	return fmt.Sprintf("PacketHeader{Version=%d, SessionID=0x%04X, SecurityFlags=0x%02X, MsgCtr=%d, SrcNode=0x%016X (present=%v), DstNode=0x%016X (present=%v)} [%d bytes: %s]",
		h.Version(), h.SessionID, h.SecurityFlags, h.MessageCounter,
		h.SourceNodeID, h.HasSourceNodeID(),
		h.DestNodeID, h.HasDestNodeID(),
		len(encoded), hex.EncodeToString(encoded))
}
