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
	"github.com/cybergarage/go-matter/matter/types"
)

// NodeID represents a node ID in the Matter protocol.
type NodeID = types.NodeID

// GroupID represents a group ID in the Matter protocol.
type GroupID = types.GroupID

// Header represents the Matter message frame header.
// 4.4.1. Message Header Field Descriptions.
type Header interface {
	// Version returns the version field (4 bits) extracted from the flags byte.
	Version() uint8
	// Flags returns the header flags byte, which contains version and presence flags.
	Flags() Flag
	// SessionID returns the session ID field (16 bits) if present, or 0 if not present.
	SessionID() uint16
	// SecurityFlags returns the security flags byte, which contains encryption and authentication flags.
	SecurityFlags() SecurityFlag
	// MessageCounter returns the message counter field (32 bits).
	MessageCounter() uint32
	// SourceNodeID returns the source node ID field (64 bits) if present, and a boolean indicating whether it is present.
	SourceNodeID() (NodeID, bool)
	// DestinationNodeID returns the destination node ID field (64 bits) if present, and a boolean indicating whether it is present.
	DestinationNodeID() (NodeID, bool)
	// GroupID returns the group ID field (64 bits) if present, and a boolean indicating whether it is present.
	GroupID() (GroupID, bool)
	// Bytes returns the byte representation of the header, ready for transmission.
	Bytes() []byte
	// String returns a human-readable string representation of the header for debugging purposes.
	String() string
}
