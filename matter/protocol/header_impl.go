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

package protocol

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
)

type header struct {
	exchangeFlags uint8
	opcode        uint8
	exchangeID    uint16
	protocolID    uint16
	vendorID      uint16
	ackCounter    uint32
}

// HeaderOption configures a Header instance.
type HeaderOption func(*header)

// WithHeaderExchangeFlags sets the exchange flags.
func WithHeaderExchangeFlags(flags uint8) HeaderOption {
	return func(h *header) {
		h.exchangeFlags = flags
	}
}

// WithHeaderOpcode sets the opcode.
func WithHeaderOpcode(opcode uint8) HeaderOption {
	return func(h *header) {
		h.opcode = opcode
	}
}

// WithHeaderExchangeID sets the exchange ID.
func WithHeaderExchangeID(exchangeID uint16) HeaderOption {
	return func(h *header) {
		h.exchangeID = exchangeID
	}
}

// WithHeaderProtocolID sets the protocol ID.
func WithHeaderProtocolID(protocolID uint16) HeaderOption {
	return func(h *header) {
		h.protocolID = protocolID
	}
}

// WithHeaderVendorID sets the vendor ID.
func WithHeaderVendorID(vendorID uint16) HeaderOption {
	return func(h *header) {
		h.vendorID = vendorID
	}
}

// WithHeaderAckCounter sets the acknowledgement counter.
func WithHeaderAckCounter(counter uint32) HeaderOption {
	return func(h *header) {
		h.ackCounter = counter
	}
}

// NewHeader creates a new Header instance with the provided options.
func NewHeader(opts ...HeaderOption) Header {
	h := &header{
		exchangeFlags: 0x00,
		opcode:        0x00,
		exchangeID:    0x0000,
		protocolID:    0x0000,
		vendorID:      0x0000,
		ackCounter:    0,
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// NewHeaderFromReader parses an exchange header from an io.Reader.
func NewHeaderFromReader(reader io.Reader) (Header, error) {
	var buf [6]byte
	_, err := io.ReadAtLeast(reader, buf[:], 6)
	if err != nil {
		return nil, err
	}

	h := &header{
		exchangeFlags: buf[0],
		opcode:        buf[1],
		exchangeID:    binary.LittleEndian.Uint16(buf[2:4]),
		protocolID:    binary.LittleEndian.Uint16(buf[4:6]),
		vendorID:      0x0000,
		ackCounter:    0,
	}

	// Read vendorID if present
	if h.HasVendorID() {
		var vbuf [2]byte
		_, err := io.ReadAtLeast(reader, vbuf[:], 2)
		if err != nil {
			return nil, err
		}
		h.vendorID = binary.LittleEndian.Uint16(vbuf[:])
	}

	// Read ackCounter if present
	if h.IsAck() {
		var abuf [4]byte
		_, err := io.ReadAtLeast(reader, abuf[:], 4)
		if err != nil {
			return nil, err
		}
		h.ackCounter = binary.LittleEndian.Uint32(abuf[:])
	}

	return h, nil
}

// NewHeaderFromBytes parses an exchange header from bytes.
func NewHeaderFromBytes(data []byte) (Header, error) {
	return NewHeaderFromReader(bytes.NewReader(data))
}

// ExchangeFlags returns the exchange flags.
func (h *header) ExchangeFlags() uint8 {
	return h.exchangeFlags
}

// Opcode returns the opcode.
func (h *header) Opcode() uint8 {
	return h.opcode
}

// ExchangeID returns the exchange ID.
func (h *header) ExchangeID() uint16 {
	return h.exchangeID
}

// ProtocolID returns the protocol ID.
func (h *header) ProtocolID() uint16 {
	return h.protocolID
}

// VendorID returns the vendor ID.
func (h *header) VendorID() uint16 {
	return h.vendorID
}

// AckCounter returns the acknowledgement counter.
func (h *header) AckCounter() uint32 {
	return h.ackCounter
}

// IsInitiator returns true if the initiator flag is set.
func (h *header) IsInitiator() bool {
	return (h.exchangeFlags & ExchangeFlagInitiator) != 0
}

// IsAck returns true if the acknowledgement flag is set.
func (h *header) IsAck() bool {
	return (h.exchangeFlags & ExchangeFlagAck) != 0
}

// IsReliabilityRequested returns true if the reliability flag is set.
func (h *header) IsReliabilityRequested() bool {
	return (h.exchangeFlags & ExchangeFlagReliability) != 0
}

// HasSecuredExtensions returns true if secured extensions flag is set.
func (h *header) HasSecuredExtensions() bool {
	return (h.exchangeFlags & ExchangeFlagSecuredExtensions) != 0
}

// HasVendorID returns true if the vendor ID flag is set.
func (h *header) HasVendorID() bool {
	return (h.exchangeFlags & ExchangeFlagVendor) != 0
}

// Bytes serializes the exchange header to bytes (little-endian).
func (h *header) Bytes() []byte {
	size := 6
	if h.HasVendorID() {
		size += 2
	}
	if h.IsAck() {
		size += 4
	}

	buf := make([]byte, size)
	buf[0] = h.exchangeFlags
	buf[1] = h.opcode
	binary.LittleEndian.PutUint16(buf[2:4], h.exchangeID)
	binary.LittleEndian.PutUint16(buf[4:6], h.protocolID)

	offset := 6
	if h.HasVendorID() {
		binary.LittleEndian.PutUint16(buf[offset:offset+2], h.vendorID)
		offset += 2
	}
	if h.IsAck() {
		binary.LittleEndian.PutUint32(buf[offset:offset+4], h.ackCounter)
	}

	return buf
}

// String returns a human-readable representation with hex dump.
func (h *header) String() string {
	encoded := h.Bytes()
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
		h.exchangeFlags, flags, h.opcode, h.exchangeID, h.protocolID,
		h.vendorID, h.HasVendorID(),
		h.ackCounter, h.IsAck(),
		len(encoded), hex.EncodeToString(encoded))
}
