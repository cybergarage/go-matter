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

package types

import (
	"github.com/cybergarage/go-matter/matter/crypto"
)

const (
	// UnicastSession indicates a unicast session.
	UnicastSession SessionType = 0x00
	// GroupSession indicates a group session.
	GroupSession SessionType = 0x01
)

// SessionType represents the session type for the message.
// 4.4.1.3. Security Flags (8 bits).
type SessionType uint8

// String returns a human-readable string representation of the SessionType.
func (s SessionType) String() string {
	switch s {
	case UnicastSession:
		return "UnicastSession"
	case GroupSession:
		return "GroupSession"
	default:
		return ""
	}
}

// SessionID represents a session identifier.
// 4.14.1.1. Protocol Overview.
// 4.13.2.4. Choosing Secure Unicast Session Identifiers.
type SessionID uint16

// NewSessionID generates a new random session ID for secure unicast sessions.
func NewSessionID() SessionID {
	b := crypto.CryptoDRBG(2)
	val := uint32(b[0])<<8 | uint32(b[1])
	return SessionID(val)
}

// NewSessionIDExcept generates a new random session ID that is different from the given session ID.
func NewSessionIDExcept(id SessionID) SessionID {
	for {
		newID := NewSessionID()
		if newID != id {
			return newID
		}
	}
}
