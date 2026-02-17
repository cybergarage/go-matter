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
	"github.com/cybergarage/go-matter/matter/encoding/json"
)

// Flag represents the message flags in the Matter protocol. It is an 8-bit field that indicates various properties of the message, such as whether it includes source/destination node IDs, whether it is a control message, etc.
// 4.4.1.1. Message Flags (8 bits).
type Flag uint8

// HeaderFlags contains flag bit positions for the header flags field.
// 4.4.1. Message Header Field Descriptions.
const (
	// VersionMask extracts the version field (bits 7-4).
	VersionMask = 0xF0
	// VersionShift is the bit position shift for the version field (bits 7-4).
	VersionShift = 4
	// SourceNodeIDPresentMask indicates whether the source node ID is present (bit 2).
	SourceNodeIDPresentMask = 0x40
	// DSIZMask extracts the DSIZ field (bits 0-1 in second byte for extended format).
	DSIZMask = 0x03
	// DestinationNodeIDPresent indicates whether the destination node ID field is the destination node ID (DSIZ == 1).
	DestinationNodeIDPresent = 0x01
	// GroupIDPresent indicates whether the destination node ID field is the group ID (DSIZ == 2).
	GroupIDPresent = 0x02
)

// Version returns the version of the message, which is encoded in the upper 4 bits of the Flag field.
func (f Flag) Version() uint8 {
	return uint8(f & VersionMask >> VersionShift)
}

// HasSourceNodeIDField returns true if the source node ID field is present, which is indicated by bit 6 of the Flag field.
func (f Flag) HasSourceNodeIDField() bool {
	return (f & SourceNodeIDPresentMask) != 0
}

// HasSourceNodeID returns true if the source node ID field is present.
func (f Flag) HasSourceNodeID() bool {
	return f.HasSourceNodeIDField()
}

// HasDestinationNodeIDField returns true if the destination node ID field is present, which is indicated by the DSIZ field (bits 0-1) of the Flag field.
func (f Flag) HasDestinationNodeIDField() bool {
	return (f & DSIZMask) != 0
}

// HasDestinationNodeID returns true if the destination node ID field is a destination node ID.
func (f Flag) HasDestinationNodeID() bool {
	return (f & DSIZMask) == DestinationNodeIDPresent
}

// HasGroupID returns true if the destination node ID field is a group ID.
func (f Flag) HasGroupID() bool {
	return (f & DSIZMask) == GroupIDPresent
}

// Map returns a map representation of the flags for easier debugging and logging.
func (f Flag) Map() map[string]any {
	return map[string]any{
		"Version": f.Version(),
		"S":       f.HasSourceNodeIDField(),
		"DSIZ":    f.HasDestinationNodeIDField(),
	}
}

// String returns a human-readable string representation of the flags for debugging purposes.
func (f Flag) String() string {
	return json.MustMarshal(f.Map())
}
