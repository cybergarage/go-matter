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

// SessionParams defines the interface for accessing session parameters as specified in section 4.13.1.
// 4.13.1. Session Parameters.
type SessionParams interface {
	// SessionIdleInterval returns the SESSION_IDLE_INTERVAL value (optional, 32-bit unsigned).
	SessionIdleInterval() (uint32, bool)
	// SessionActiveInterval returns the SESSION_ACTIVE_INTERVAL value (optional, 32-bit unsigned).
	SessionActiveInterval() (uint32, bool)
	// SessionActiveThreshold returns the SESSION_ACTIVE_THRESHOLD value (optional, 16-bit unsigned).
	SessionActiveThreshold() (uint16, bool)
	// DataModelRevision returns the DATA_MODEL_REVISION value (16-bit unsigned).
	DataModelRevision() uint16
	// InteractionModelRevision returns the INTERACTION_MODEL_REVISION value (16-bit unsigned).
	InteractionModelRevision() uint16
	// SpecificationVersion returns the SPECIFICATION_VERSION value (32-bit unsigned).
	SpecificationVersion() uint32
	// MaxPathsPerInvoke returns the MAX_PATHS_PER_INVOKE value (16-bit unsigned).
	MaxPathsPerInvoke() uint16
	// SupportedTransports returns the SUPPORTED_TRANSPORTS value (16-bit unsigned).
	SupportedTransports() uint16
	// MaxTCPMessageSize returns the MAX_TCP_MESSAGE_SIZE value (optional, 32-bit unsigned).
	MaxTCPMessageSize() (uint32, bool)
	// Map returns a map representation of the session parameters.
	Map() map[string]any
	// String returns a string representation of the session parameters.
	String() string
}
