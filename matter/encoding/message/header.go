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

// 4.4.1. Message Header Field Descriptions
// Header represents the Matter message frame header.
// Reference: Matter Core Spec 1.5, Section 4.4 (Message Frame Format).
type Header interface {
	// Flags returns the header flags byte, which contains version and presence flags.
	Flags() uint8
	// SessionID returns the session ID field (16 bits) if present, or 0 if not present.
	SessionID() uint16
	// SecurityFlags returns the security flags byte, which contains encryption and authentication flags.
	SecurityFlags() uint8
	// MessageCounter returns the message counter field (32 bits).
	MessageCounter() uint32
	// SourceNodeID returns the source node ID field (64 bits) if present, or 0 if not present.
	SourceNodeID() uint64
	// DestNodeID returns the destination node ID field (64 bits) if present, or 0 if not present.
	DestNodeID() uint64
	// Version returns the version field (4 bits) extracted from the flags byte.
	Version() uint8
	// HasSourceNodeID indicates whether the source node ID is present.
	HasSourceNodeID() bool
	// HasDestNodeID indicates whether the destination node ID is present.
	HasDestNodeID() bool
	// Encode returns the byte representation of the header, ready for transmission.
	Encode() []byte
	// String returns a human-readable string representation of the header for debugging purposes.
	String() string
}

// HeaderFlags contains flag bit positions for the header flags field.
// Reference: Matter Core Spec 1.5, Section 4.4.
const (
	// VersionMask extracts the version field (bits 0-3).
	VersionMask = 0x0F
	// FlagDestNodeIDPresent indicates destination node ID is present (bit 5).
	FlagDestNodeIDPresent = 0x20
	// FlagSourceNodeIDPresent indicates source node ID is present (bit 6).
	FlagSourceNodeIDPresent = 0x40
	// DSIZ mask (bits 6-7, in second byte for extended format).
	// Note: DSIZ is not used in this minimal implementation.
	DSIZMask  = 0xC0
	DSIZShift = 6
)

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
