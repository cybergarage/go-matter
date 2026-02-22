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

package mrp

import (
	"github.com/cybergarage/go-matter/matter/encoding/message"
)

// Message represents a complete message with frame header, protocol header, and payload.
// 4.4. Message Frame Format.
type Message = message.Message

// Ack defines the interface for MRP ACK messages.
// 4.12. Message Reliability Protocol (MRP).
type Ack interface {
	AckHelper
	// Message returns the underlying message that this ACK represents.
	Message() Message
	// IsReliability returns true if the ACK message is a reliability ACK.
	IsReliability() bool
	// IsAcknowledgement returns true if the ACK message is an acknowledgement.
	IsAcknowledgement() bool
	// MessageCounter returns the acknowledgement counter value from the ACK message if present.
	MessageCounter() MessageCounter
	// Bytes serializes the ACK message to bytes for transmission.
	Bytes() []byte
}

// AckHelper defines additional helper methods for ACK messages, such as debugging output.
type AckHelper interface {
	// Map returns a map representation of the ACK message for debugging purposes.
	Map() map[string]any
	// String returns a human-readable string representation of the ACK message.
	String() string
}
