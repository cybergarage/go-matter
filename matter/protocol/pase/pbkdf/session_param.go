// Copyright (C) 2025 The go-matter Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pbkdf

import (
	"time"

	"github.com/cybergarage/go-matter/matter/encoding/tlv"
)

// 4.13.1. Session Parameters.
const (
	DefaultSessionIdleDuration      = time.Duration(500 * time.Millisecond)
	DefaultSessionActiveInterval    = time.Duration(300 * time.Millisecond)
	DefaultSessionActiveThreshold   = time.Duration(4000 * time.Millisecond)
	DefaultDataModelRevision        = Revision(16)
	DefaultInteractionModelRevision = Revision(10)
	DefaultSpecificationVersion     = Version(0x01030000)
	DefaultMaxPathsPerInvoke        = uint16(1)
	DefaultSupportedTransports      = MRP
	MaxTCPMessageSize               = uint32(64000)
)

// SessionParams defines the interface for accessing session parameters as specified in section 4.13.1.
// 4.13.1. Session Parameters.
type SessionParams interface {
	SessionParamsHelper
	// SessionIdleInterval returns the SESSION_IDLE_INTERVAL value (optional, 32-bit unsigned).
	SessionIdleInterval() (time.Duration, bool)
	// SessionActiveInterval returns the SESSION_ACTIVE_INTERVAL value (optional, 32-bit unsigned).
	SessionActiveInterval() (time.Duration, bool)
	// SessionActiveThreshold returns the SESSION_ACTIVE_THRESHOLD value (optional, 16-bit unsigned).
	SessionActiveThreshold() (time.Duration, bool)
	// DataModelRevision returns the DATA_MODEL_REVISION value (16-bit unsigned).
	DataModelRevision() Revision
	// InteractionModelRevision returns the INTERACTION_MODEL_REVISION value (16-bit unsigned).
	InteractionModelRevision() Revision
	// SpecificationVersion returns the SPECIFICATION_VERSION value (32-bit unsigned).
	SpecificationVersion() Version
	// MaxPathsPerInvoke returns the MAX_PATHS_PER_INVOKE value (16-bit unsigned).
	MaxPathsPerInvoke() uint16
	// SupportedTransports returns the SUPPORTED_TRANSPORTS value (16-bit unsigned).
	SupportedTransports() TransportMode
	// MaxTCPMessageSize returns the MAX_TCP_MESSAGE_SIZE value (optional, 32-bit unsigned).
	MaxTCPMessageSize() (uint32, bool)
}

// SessionParamsHelper defines the interface for encoding session parameters into TLV and providing map and string representations.
type SessionParamsHelper interface {
	// Encode encodes the session parameters into the provided TLV encoder.
	Encode(enc tlv.Encoder, tagNum uint8) error
	// Map returns a map representation of the session parameters.
	Map() map[string]any
	// String returns a string representation of the session parameters.
	String() string
}
