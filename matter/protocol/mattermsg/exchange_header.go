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

// ExchangeHeader represents the Matter exchange layer header.
// Reference: Matter Core Spec 1.5, Section 4.11 (Exchange Layer)
type ExchangeHeader struct {
	// ExchangeFlags contains control flags for this exchange
	ExchangeFlags uint8
	// Opcode identifies the protocol operation
	Opcode uint8
	// ExchangeID identifies the exchange session
	ExchangeID uint16
	// ProtocolID identifies the protocol being used
	ProtocolID uint16
	// VendorID is optional, present if V flag is set
	VendorID uint16
	// AckCounter is optional, present if A flag is set (references acknowledged message)
	AckCounter uint32
}

// Exchange flag bit positions (from Matter spec)
const (
	// ExchangeFlagInitiator (I) indicates the sender is the initiator (bit 0)
	ExchangeFlagInitiator = 0x01
	// ExchangeFlagAck (A) indicates this is an acknowledgement (bit 1)
	ExchangeFlagAck = 0x02
	// ExchangeFlagReliability (R) indicates reliable transmission is requested (bit 2)
	ExchangeFlagReliability = 0x04
	// ExchangeFlagSecuredExtensions (SX) indicates secured extensions are present (bit 3)
	ExchangeFlagSecuredExtensions = 0x08
	// ExchangeFlagVendor (V) indicates a vendor-specific protocol (bit 4)
	ExchangeFlagVendor = 0x10
)

// IsInitiator returns true if the initiator flag is set.
func (h *ExchangeHeader) IsInitiator() bool {
	return (h.ExchangeFlags & ExchangeFlagInitiator) != 0
}

// IsAck returns true if the acknowledgement flag is set.
func (h *ExchangeHeader) IsAck() bool {
	return (h.ExchangeFlags & ExchangeFlagAck) != 0
}

// IsReliabilityRequested returns true if the reliability flag is set.
func (h *ExchangeHeader) IsReliabilityRequested() bool {
	return (h.ExchangeFlags & ExchangeFlagReliability) != 0
}

// HasSecuredExtensions returns true if secured extensions flag is set.
func (h *ExchangeHeader) HasSecuredExtensions() bool {
	return (h.ExchangeFlags & ExchangeFlagSecuredExtensions) != 0
}

// HasVendorID returns true if the vendor ID flag is set.
func (h *ExchangeHeader) HasVendorID() bool {
	return (h.ExchangeFlags & ExchangeFlagVendor) != 0
}

// Encode serializes the exchange header to bytes (little-endian).
func (h *ExchangeHeader) Encode() []byte {
	// Base size: flags(1) + opcode(1) + exchangeID(2) + protocolID(2) = 6 bytes
	size := 6
	if h.HasVendorID() {
		size += 2
	}
	if h.IsAck() {
		size += 4
	}

	buf := make([]byte, size)
	buf[0] = h.ExchangeFlags
	buf[1] = h.Opcode
	binary.LittleEndian.PutUint16(buf[2:4], h.ExchangeID)
	binary.LittleEndian.PutUint16(buf[4:6], h.ProtocolID)

	offset := 6
	if h.HasVendorID() {
		binary.LittleEndian.PutUint16(buf[offset:offset+2], h.VendorID)
		offset += 2
	}
	if h.IsAck() {
		binary.LittleEndian.PutUint32(buf[offset:offset+4], h.AckCounter)
	}

	return buf
}

// DecodeExchangeHeader parses an exchange header from bytes (little-endian).
// Returns the header and the number of bytes consumed, or an error.
func DecodeExchangeHeader(data []byte) (*ExchangeHeader, int, error) {
	if len(data) < 6 {
		return nil, 0, fmt.Errorf("exchange header too short: need at least 6 bytes, got %d", len(data))
	}

	h := &ExchangeHeader{
		ExchangeFlags: data[0],
		Opcode:        data[1],
		ExchangeID:    binary.LittleEndian.Uint16(data[2:4]),
		ProtocolID:    binary.LittleEndian.Uint16(data[4:6]),
	}

	offset := 6

	if h.HasVendorID() {
		if len(data) < offset+2 {
			return nil, 0, fmt.Errorf("exchange header truncated: vendor ID expected but only %d bytes remain", len(data)-offset)
		}
		h.VendorID = binary.LittleEndian.Uint16(data[offset : offset+2])
		offset += 2
	}

	if h.IsAck() {
		if len(data) < offset+4 {
			return nil, 0, fmt.Errorf("exchange header truncated: ack counter expected but only %d bytes remain", len(data)-offset)
		}
		h.AckCounter = binary.LittleEndian.Uint32(data[offset : offset+4])
		offset += 4
	}

	return h, offset, nil
}

// String returns a human-readable representation with hex dump.
func (h *ExchangeHeader) String() string {
	encoded := h.Encode()
	flags := []string{}
	if h.IsInitiator() {
		flags = append(flags, "I")
	}
	if h.IsAck() {
		flags = append(flags, "A")
	}
	if h.IsReliabilityRequested() {
		flags = append(flags, "R")
	}
	if h.HasSecuredExtensions() {
		flags = append(flags, "SX")
	}
	if h.HasVendorID() {
		flags = append(flags, "V")
	}

	return fmt.Sprintf("ExchangeHeader{Flags=0x%02X [%v], Opcode=0x%02X, ExchID=0x%04X, ProtoID=0x%04X, VendorID=0x%04X (present=%v), AckCtr=%d (present=%v)} [%d bytes: %s]",
		h.ExchangeFlags, flags, h.Opcode, h.ExchangeID, h.ProtocolID,
		h.VendorID, h.HasVendorID(),
		h.AckCounter, h.IsAck(),
		len(encoded), hex.EncodeToString(encoded))
}
