// Copyright (C) 2024 The go-matter Authors. All rights reserved.
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

import "github.com/cybergarage/go-matter/matter/crypto"

// ExchangeID represents a exchange ID.
// 4.4.3. Protocol Header Field Descriptions
// 4.4.3.3. Exchange ID (16 bits).
// 4.10.2. Exchange ID.
type ExchangeID uint16

const (
	minExchangeID      ExchangeID = 0x0001
	maxExchangeID      ExchangeID = 0xFFFF
	overflowExchangeID ExchangeID = 0x0000
)

// NewFirstExchangeID generates a new random ExchangeID for the first exchange of a given initiator node.
func NewFirstExchangeID() ExchangeID {
	// 4.10.2. Exchange ID
	// The first Exchange ID for a given Initiator Node SHALL be a random integer.
	b := crypto.CryptoDRBG(2)
	v := uint16(b[0])<<8 | uint16(b[1])
	v = v%(uint16(maxExchangeID)-uint16(minExchangeID)) + uint16(minExchangeID)
	return ExchangeID(v)
}

// Compare compares this ExchangeID with another, returning -1 if this is less, 0 if equal, and 1 if greater.
func (id ExchangeID) Compare(other ExchangeID) int {
	if id < other {
		if id == overflowExchangeID {
			// 4.10.2. Exchange ID
			// The first Exchange ID for a given Initiator Node SHALL be a random integer.
			return 1
		}
		return -1
	}
	if id > other {
		return 1
	}
	return 0
}

// Next returns the next ExchangeID, wrapping around to 0 after reaching the maximum value.
func (id ExchangeID) Next() ExchangeID {
	// 4.10.2. Exchange ID
	// An Exchange ID is an unsigned integer that rolls over to zero when its maximum value is exceeded.
	if id == maxExchangeID {
		return overflowExchangeID
	}
	return id + 1
}
