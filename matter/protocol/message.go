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

package protocol

import (
	"github.com/cybergarage/go-matter/matter/encoding/message"
)

// Message represents a complete message with frame header, protocol header, and payload.
// 4.4. Message Frame Format.
type Message interface {
	// FrameHeader represents the frame header of the message.
	message.Header
	// Header represents the protocol header of the message.
	Header
	// Extensions returns the message extensions, if any.
	Extensions() ([]byte, bool)
	// Payload returns the payload of the message.
	Payload() []byte
	// Bytes serializes the complete message to bytes.
	Bytes() []byte
	// Map returns a map representation of the message for easier debugging and logging.
	Map() map[string]any
	// String returns a human-readable representation of the message for debugging purposes.
	String() string
}
