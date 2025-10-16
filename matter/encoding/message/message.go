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

package message

// FrameVersion represents the version field in the frame control.
type FrameVersion uint8

const (
	// FrameVersion1 represents Matter message frame version 1.
	FrameVersion1 FrameVersion = 0x00
)

// FrameType represents a message/frame type enumeration.
type FrameType uint8

const (
	// FrameTypeUnspecified is a placeholder frame type.
	FrameTypeUnspecified FrameType = 0x00
	// FrameTypeSecure is a placeholder secure frame type.
	FrameTypeSecure FrameType = 0x01
	// FrameTypeControl is a placeholder control frame type.
	FrameTypeControl FrameType = 0x02
)

// Message defines the interface for a Matter-like message frame.
// All fields are read-only; mutation is by WithFrameOption only.
type Message interface {
	// Version returns the frame version.
	Version() FrameVersion
	// Type returns the frame type.
	Type() FrameType
	// HasSourceNodeID reports whether a Source Node ID is present.
	HasSourceNodeID() bool
	// HasDestNodeID reports whether a Destination Node ID is present.
	HasDestNodeID() bool
	// SessionID returns the session identifier.
	SessionID() uint16
	// SecurityFlags returns the raw security flags byte.
	SecurityFlags() uint8
	// MessageCounter returns the message counter.
	MessageCounter() uint32
	// SourceNodeID returns the source node identifier.
	SourceNodeID() uint64
	// DestNodeID returns the destination node identifier.
	DestNodeID() uint64
	// Payload returns the payload bytes.
	Payload() []byte
	// MIC returns the Message Integrity Code (authentication tag) if present.
	MIC() []byte
}

// WithMessageOption is a functional option type for basicFrame construction.
// Each option mutates the basicFrame pointer during creation.
type WithMessageOption func(*message)

// message is the default concrete implementation of Frame.
type message struct {
	version        FrameVersion
	ftype          FrameType
	hasSourceNode  bool
	hasDestNode    bool
	sessionID      uint16
	securityFlags  uint8
	messageCounter uint32
	sourceNodeID   uint64
	destNodeID     uint64
	payload        []byte
	mic            []byte
}

// NewBasicFrameWith creates a new basicFrame implementing Frame, applying any options.
func NewBasicFrameWith(opts ...WithMessageOption) Message {
	return newBasicFrameWith(opts...)
}

// newBasicFrameWith creates a new basicFrame implementing Frame with all fields set to spec default values and applies any options.
// Default values:
//
//	Version: FrameVersion1 (0x00)
//	Type: FrameTypeUnspecified (0x00)
//	HasSourceNodeID: false
//	HasDestNodeID: false
//	SessionID: 0x0000
//	SecurityFlags: 0x00
//	MessageCounter: 0x00000000
//	SourceNodeID: 0x0
//	DestNodeID: 0x0
//	Payload: nil
//	MIC: nil
func newBasicFrameWith(opts ...WithMessageOption) *message {
	f := &message{
		version:        FrameVersion1,
		ftype:          FrameTypeUnspecified,
		hasSourceNode:  false,
		hasDestNode:    false,
		sessionID:      0x0000,
		securityFlags:  0x00,
		messageCounter: 0x00000000,
		sourceNodeID:   0x0,
		destNodeID:     0x0,
		payload:        nil,
		mic:            nil,
	}
	for _, opt := range opts {
		opt(f)
	}
	return f
}

// Version implements Frame.
func (f *message) Version() FrameVersion { return f.version }

// SetVersion implements Frame (fluent).
func (f *message) SetVersion(v FrameVersion) *message { f.version = v; return f }

// Type implements Frame.
func (f *message) Type() FrameType { return f.ftype }

// SetType implements Frame (fluent).
func (f *message) SetType(t FrameType) *message { f.ftype = t; return f }

// HasSourceNodeID implements Frame.
func (f *message) HasSourceNodeID() bool { return f.hasSourceNode }

// SetSourceNodeIDPresent implements Frame (fluent).
func (f *message) SetSourceNodeIDPresent(p bool) *message { f.hasSourceNode = p; return f }

// HasDestNodeID implements Frame.
func (f *message) HasDestNodeID() bool { return f.hasDestNode }

// SetDestNodeIDPresent implements Frame (fluent).
func (f *message) SetDestNodeIDPresent(p bool) *message { f.hasDestNode = p; return f }

// SessionID implements Frame.
func (f *message) SessionID() uint16 { return f.sessionID }

// SetSessionID implements Frame (fluent).
func (f *message) SetSessionID(id uint16) *message { f.sessionID = id; return f }

// SecurityFlags implements Frame.
func (f *message) SecurityFlags() uint8 { return f.securityFlags }

// SetSecurityFlags implements Frame (fluent).
func (f *message) SetSecurityFlags(sf uint8) *message { f.securityFlags = sf; return f }

// MessageCounter implements Frame.
func (f *message) MessageCounter() uint32 { return f.messageCounter }

// SetMessageCounter implements Frame (fluent).
func (f *message) SetMessageCounter(mc uint32) *message { f.messageCounter = mc; return f }

// SourceNodeID implements Frame.
func (f *message) SourceNodeID() uint64 { return f.sourceNodeID }

// SetSourceNodeID implements Frame (fluent).
func (f *message) SetSourceNodeID(id uint64) *message { f.sourceNodeID = id; return f }

// DestNodeID implements Frame.
func (f *message) DestNodeID() uint64 { return f.destNodeID }

// SetDestNodeID implements Frame (fluent).
func (f *message) SetDestNodeID(id uint64) *message { f.destNodeID = id; return f }

// Payload implements Frame.
func (f *message) Payload() []byte { return f.payload }

// SetPayload implements Frame (fluent).
func (f *message) SetPayload(p []byte) *message { f.payload = p; return f }

// MIC implements Frame.
func (f *message) MIC() []byte { return f.mic }

// SetMIC implements Frame (fluent).
func (f *message) SetMIC(m []byte) *message { f.mic = m; return f }

// WithVersion sets the frame version field.
func WithVersion(v FrameVersion) WithMessageOption {
	return func(f *message) { f.version = v }
}

// WithType sets the frame type field.
func WithType(t FrameType) WithMessageOption {
	return func(f *message) { f.ftype = t }
}

// WithSourceNodeIDPresent sets the source node ID presence flag.
func WithSourceNodeIDPresent(p bool) WithMessageOption {
	return func(f *message) { f.hasSourceNode = p }
}

// WithDestNodeIDPresent sets the destination node ID presence flag.
func WithDestNodeIDPresent(p bool) WithMessageOption {
	return func(f *message) { f.hasDestNode = p }
}

// WithSessionID sets the session ID field.
func WithSessionID(id uint16) WithMessageOption {
	return func(f *message) { f.sessionID = id }
}

// WithSecurityFlags sets the security flags field.
func WithSecurityFlags(flags uint8) WithMessageOption {
	return func(f *message) { f.securityFlags = flags }
}

// WithMessageCounter sets the message counter field.
func WithMessageCounter(mc uint32) WithMessageOption {
	return func(f *message) { f.messageCounter = mc }
}

// WithSourceNodeID sets the source node ID field.
func WithSourceNodeID(id uint64) WithMessageOption {
	return func(f *message) { f.sourceNodeID = id }
}

// WithDestNodeID sets the destination node ID field.
func WithDestNodeID(id uint64) WithMessageOption {
	return func(f *message) { f.destNodeID = id }
}

// WithPayload sets the payload field.
func WithPayload(p []byte) WithMessageOption {
	return func(f *message) { f.payload = p }
}

// WithMIC sets the MIC field.
func WithMIC(m []byte) WithMessageOption {
	return func(f *message) { f.mic = m }
}
