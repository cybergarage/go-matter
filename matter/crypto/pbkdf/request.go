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

// ParamRequest represents the PBKDF parameter request message sent by the initiator during PASE handshake.
// 4.14.1. Passcode-Authenticated Session Establishment (PASE).
type ParamRequest interface {
	// InitiatorRandom returns the initiator random value from the request.
	InitiatorRandom() []byte
	// InitiatorSessionID returns the initiator session ID from the request.
	InitiatorSessionID() uint16
	// PasscodeID returns the passcode ID from the request.
	PasscodeID() uint16
	// HasPBKDFParameters indicates whether the request includes PBKDF parameters.
	HasPBKDFParameters() bool
	// SessionParams returns the session parameters and a boolean indicating if they are present.
	SessionParams() (SessionParams, bool)
	// Validate validates the ParamRequest according to the constraints specified in section 4.14.1.
	Validate() error
	// Bytes returns the byte representation of the ParamRequest message, ready for transmission.
	Bytes() ([]byte, error)
	// Map returns a map representation of the ParamRequest.
	Map() map[string]any
	// String returns a human-readable string representation of the ParamRequest.
	String() string
}
