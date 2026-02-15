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
	// Bytes returns the byte representation of the ParamRequest message, ready for transmission.
	Bytes() ([]byte, error)
}
