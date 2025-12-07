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

// Flag represents a message flag.
// 4.4.1.2. Message Flags (8 bits).
type Flag uint8

// Version returns the matter message format version.
func (flag Flag) Version() int {
	return int((flag & 0xF0) >> 4)
}

// HasSourceNodeID returns true if the message has a source node ID.
func (flag Flag) HasSourceNodeID() bool {
	return (flag & 0x04) != 0
}

// HasDestinationNodeID returns true if the message has a destination node ID.
func (flag Flag) HasDestinationNodeID() bool {
	return (flag & 0x02) != 0
}
