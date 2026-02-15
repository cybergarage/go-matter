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

// 4.4. Message Frame Format
// Frame represents a complete Matter message frame (header + payload).
type Frame interface {
	// Header returns the header of the frame.
	Header() Header
	// Payload returns the payload of the frame.
	Payload() []byte
	// Encode returns the byte representation of the complete frame, ready for transmission.
	Encode() []byte
	// String returns a human-readable representation of the frame for debugging purposes.
	String() string
}

// NewFrame creates a new Frame instance.
func NewFrame(header Header, payload []byte) Frame {
	return &frame{
		header:  header,
		payload: payload,
	}
}
