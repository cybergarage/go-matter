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

// ParamResponse represents the PBKDF parameter response message sent by the responder during PASE handshake.
// 4.14.1. Passcode-Authenticated Session Establishment (PASE).
type ParamResponse interface {
	// InitiatorRandom returns the initiator random value from the request.
	InitiatorRandom() []byte
	// ResponderRandom returns the responder random value from the response.
	ResponderRandom() []byte
	// ResponderSessionID returns the responder session ID from the response.
	ResponderSessionID() uint16
	// PBKDFParams returns the PBKDF parameters included in the response.
	PBKDFParams() Params
	// ResponderSessionParams returns the responder session parameters and a boolean indicating if they are present.
	ResponderSessionParams() (SessionParams, bool)
	// Bytes returns the byte representation of the ParamResponse message, ready for transmission.
	Bytes() ([]byte, error)
	// Map returns a map representation of the ParamResponse.
	Map() map[string]any
	// String returns a human-readable string representation of the ParamResponse.
	String() string
}
