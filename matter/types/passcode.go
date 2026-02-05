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
	"fmt"
)

// Passcode represents a passcode.
type Passcode uint32

// NewPasscode creates a new Passcode.
func NewPasscode(code uint32) Passcode {
	return Passcode(code)
}

// Bytes returns the little-endian 4-octet representation of the Passcode.
func (p Passcode) Bytes() []byte {
	return []byte(p.String())
}

// String returns the string representation of the Passcode.
func (p Passcode) String() string {
	// 3.10. Password-Authenticated Key Exchange (PAKE)
	// passcode, is the Passcode defined in Section 5.1.1.6, “Passcode”, serialized as little-endian over 4
	// octets. For example, passcode 18924017 would be encoded as the octet string f1:c1:20:01 and
	// the passcode 00000005 would be encoded as the octet string 05:00:00:00.
	b := make([]byte, 4)
	b[0] = byte(p & 0xff)
	b[1] = byte((p >> 8) & 0xff)
	b[2] = byte((p >> 16) & 0xff)
	b[3] = byte((p >> 24) & 0xff)
	return fmt.Sprintf("%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3])
}
