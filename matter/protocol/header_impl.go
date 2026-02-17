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
	"encoding/json"
	"fmt"
	"io"
)

const (
	minHeaderSize = 6
)

type header struct {
	exchangeFlags     ExchangeFlag
	opcode            uint8
	exchangeID        uint16
	protocolID        uint16
	vendorID          uint16
	ackCounter        uint32
	securedExtensions []byte
}

// HeaderOption configures a Header instance.
type HeaderOption func(*header)

// WithHeaderExchangeFlags sets the exchange flags.
func WithHeaderExchangeFlags(flags ExchangeFlag) HeaderOption {
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
func WithHeaderExchangeID(exchangeID ExchangeID) HeaderOption {
	return func(h *header) {
		h.exchangeID = uint16(exchangeID)
	}
}

// WithHeaderProtocolID sets the protocol ID.
func WithHeaderProtocolID(protocolID ProtocolID) HeaderOption {
	return func(h *header) {
		h.protocolID = uint16(protocolID)
	}
}

// WithHeaderVendorID sets the vendor ID.
func WithHeaderVendorID(vendorID VendorID) HeaderOption {
	return func(h *header) {
		h.exchangeFlags |= ExchangeFlagVendor
		h.vendorID = uint16(vendorID)
	}
}

// WithHeaderAckCounter sets the acknowledgement counter.
func WithHeaderAckCounter(counter uint32) HeaderOption {
	return func(h *header) {
		h.exchangeFlags |= ExchangeFlagAck
		h.ackCounter = counter
	}
}

// WithHeaderSecuredExtensions sets the secured extensions.
func WithHeaderSecuredExtensions(ext []byte) HeaderOption {
	return func(h *header) {
		h.exchangeFlags |= ExchangeFlagSecuredExtensions
		h.securedExtensions = ext
	}
}

// NewHeader creates a new Header instance with the provided options.
func NewHeader(opts ...HeaderOption) Header {
	h := &header{
		exchangeFlags:     0x00,
		opcode:            0x00,
		exchangeID:        0x0000,
		protocolID:        0x0000,
		vendorID:          0x0000,
		ackCounter:        0,
		securedExtensions: []byte{},
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// NewHeaderFromReader parses an exchange header from an io.Reader.
func NewHeaderFromReader(reader io.Reader) (Header, error) {
	var buf [minHeaderSize]byte
	_, err := io.ReadAtLeast(reader, buf[:], minHeaderSize)
	if err != nil {
		return nil, err
	}
	h := &header{
		exchangeFlags:     ExchangeFlag(buf[0]),
		opcode:            buf[1],
		exchangeID:        binary.LittleEndian.Uint16(buf[2:4]),
		protocolID:        binary.LittleEndian.Uint16(buf[4:6]),
		vendorID:          0x0000,
		ackCounter:        0,
		securedExtensions: []byte{},
	}

	// 4.4.3.5. Protocol Vendor ID (16 bits)
	if h.HasVendorID() {
		var vbuf [2]byte
		_, err := io.ReadAtLeast(reader, vbuf[:], 2)
		if err != nil {
			return nil, err
		}
		h.vendorID = binary.LittleEndian.Uint16(vbuf[:])
	}

	// 4.4.3.6. Acknowledged Message Counter (32 bits)
	if h.IsAcknowledgement() {
		var abuf [4]byte
		_, err := io.ReadAtLeast(reader, abuf[:], 4)
		if err != nil {
			return nil, err
		}
		h.ackCounter = binary.LittleEndian.Uint32(abuf[:])
	}

	// 4.4.3.7. Secured Extensions (variable)
	if h.HasSecuredExtensions() {
		payload, err := NewPayloadFromPrefixedReader(reader)
		if err != nil {
			return nil, err
		}
		h.securedExtensions = payload.Bytes()
	}

	return h, nil
}

// NewHeaderFromBytes parses an exchange header from bytes.
func NewHeaderFromBytes(data []byte) (Header, error) {
	return NewHeaderFromReader(bytes.NewReader(data))
}

// ExchangeFlags returns the exchange flags.
func (h *header) ExchangeFlags() ExchangeFlag {
	return h.exchangeFlags
}

// Opcode returns the opcode.
func (h *header) Opcode() uint8 {
	return h.opcode
}

// ExchangeID returns the exchange ID.
func (h *header) ExchangeID() ExchangeID {
	return ExchangeID(h.exchangeID)
}

// ProtocolID returns the protocol ID.
func (h *header) ProtocolID() ProtocolID {
	return ProtocolID(h.protocolID)
}

// IsInitiator returns true if the initiator flag is set.
func (h *header) IsInitiator() bool {
	return h.exchangeFlags.IsInitiator()
}

// IsAcknowledgement returns true if the acknowledgement flag is set.
func (h *header) IsAcknowledgement() bool {
	return h.exchangeFlags.IsAcknowledgement()
}

// IsReliabilityRequested returns true if the reliability flag is set.
func (h *header) IsReliability() bool {
	return h.exchangeFlags.IsReliability()
}

// HasSecuredExtensions returns true if secured extensions flag is set.
func (h *header) HasSecuredExtensions() bool {
	return h.exchangeFlags.HasSecuredExtensions()
}

// HasVendorID returns true if the vendor ID flag is set.
func (h *header) HasVendorID() bool {
	return h.exchangeFlags.HasVendorID()
}

// VendorID returns the vendor ID if present.
func (h *header) VendorID() (VendorID, bool) {
	if !h.HasVendorID() {
		return 0, false
	}
	return VendorID(h.vendorID), true
}

// AckCounter returns the acknowledgement counter if present.
func (h *header) AckCounter() (uint32, bool) {
	if !h.IsAcknowledgement() {
		return 0, false
	}
	return h.ackCounter, true
}

// SecuredExtensions returns the secured extensions bytes if present, along with a boolean indicating their presence.
func (h *header) SecuredExtensions() ([]byte, bool) {
	if !h.HasSecuredExtensions() {
		return nil, false
	}
	return h.securedExtensions, true
}

// Bytes serializes the exchange header to bytes (little-endian).
func (h *header) Bytes() []byte {
	buf := make([]byte, minHeaderSize)
	buf[0] = byte(h.exchangeFlags)
	buf[1] = h.opcode
	binary.LittleEndian.PutUint16(buf[2:4], h.exchangeID)
	binary.LittleEndian.PutUint16(buf[4:6], h.protocolID)

	if h.HasVendorID() {
		buf = binary.LittleEndian.AppendUint16(buf, h.vendorID)
	}
	if h.IsAcknowledgement() {
		buf = binary.LittleEndian.AppendUint32(buf, h.ackCounter)
	}
	if ext, ok := h.SecuredExtensions(); ok {
		payload := NewPayloadWithBytes(ext)
		buf = append(buf, payload.PrefixedBytes()...)
	}

	return buf
}

// Map returns a map representation of the header for easier debugging and logging.
func (h *header) Map() map[string]any {
	m := map[string]any{
		"ExchangeFlags": fmt.Sprintf("0x%02X", h.exchangeFlags),
		"Opcode":        fmt.Sprintf("0x%02X", h.opcode),
		"ExchangeID":    fmt.Sprintf("0x%04X", h.exchangeID),
		"ProtocolID":    fmt.Sprintf("0x%04X", h.protocolID),
	}

	if h.HasVendorID() {
		m["VendorID"] = fmt.Sprintf("0x%04X", h.vendorID)
	}
	if h.IsAcknowledgement() {
		m["AckCounter"] = h.ackCounter
	}
	if ext, ok := h.SecuredExtensions(); ok {
		m["SecuredExtensions"] = fmt.Sprintf("%X", ext)
	}

	return m
}

// String returns a human-readable representation with hex dump.
func (h *header) String() string {
	s, _ := json.Marshal(h.Map())
	return string(s)
}
