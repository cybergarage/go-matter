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
	"github.com/cybergarage/go-matter/matter/encoding/json"
	"github.com/cybergarage/go-matter/matter/types"
)

// SecurityFlag represents the security flags in the message header as defined in Matter specification section
// 4.4.1.3. Security Flags (8 bits).
type SecurityFlag uint8

// SessionType represents the session type for the message.
// 4.4.1.3. Security Flags (8 bits).
type SessionType = types.SessionType

const (
	// PrivacyMask indicates that the message is encoded with privacy enhancements.
	// P Flag (1 bit, position 7).
	PrivacyMask = 0x80
	// ControlMessageMask indicates that the message is a control message.
	// C Flag (1 bit, position 6).
	ControlMessageMask = 0x40
	// MessageExtensionsMask indicates that the message includes additional security features or extensions.
	// MX Flag (1 bit, position 5).
	MessageExtensionsMask = 0x20
	// SessionTypeMask specifies the session type for the message.
	// Session Type (2 bit, position 0-1).
	SessionTypeMask = 0x03
)

// HasPrivacy returns true if the privacy flag is set in the security flags.
func (f SecurityFlag) HasPrivacy() bool {
	return f&PrivacyMask != 0
}

// IsControlMessage returns true if the control message flag is set in the security flags.
func (f SecurityFlag) IsControlMessage() bool {
	return f&ControlMessageMask != 0
}

// HasMessageExtensions returns true if the message extensions flag is set in the security flags.
func (f SecurityFlag) HasMessageExtensions() bool {
	return f&MessageExtensionsMask != 0
}

// SessionType returns the session type for the message.
func (f SecurityFlag) SessionType() SessionType {
	return SessionType(f & SessionTypeMask)
}

// Map returns a map representation of the security flags for easier debugging and logging.
func (f SecurityFlag) Map() map[string]any {
	return map[string]any{
		"P":           f.HasPrivacy(),
		"C":           f.IsControlMessage(),
		"MX":          f.HasMessageExtensions(),
		"SessionType": f.SessionType(),
	}
}

// String returns a human-readable string representation for debugging purposes.
func (f SecurityFlag) String() string {
	return json.MustMarshal(f.Map())
}
