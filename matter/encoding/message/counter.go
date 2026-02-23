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
	"github.com/cybergarage/go-matter/matter/crypto"
)

const (
	maxMessageCounter        = ^uint32(0) // 2^32 - 1
	minInitialMessageCounter = 1
	maxInitialMessageCounter = 268435456 // 2^28
)

// MessageCounter tracks outbound message counters for a session.
// 4.6. Message Counters
// 4.4.1.4. Message Counter (32 bits).
type MessageCounter uint32

// NewMessageCounter creates a new initialized random message counter.
// 4.6. Message Counters
func NewMessageCounter() MessageCounter {
	// 4.6.1.1. Message Counter Initialization
	// Generate a random uint32 in [min, max)
	const min = minInitialMessageCounter
	const max = maxInitialMessageCounter
	b := crypto.CryptoDRBG(4)
	val := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	val = val%(max-min) + min
	return MessageCounter(val)
}

// Next returns the next message counter value and increments the internal counter.
// This method is thread-safe using atomic operations.
func (mc MessageCounter) Next() MessageCounter {
	if mc == MessageCounter(maxMessageCounter) {
		return 0
	}
	return mc + 1
}
