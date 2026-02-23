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

// NodeID represents a node ID.
// 2.5.5. Node Identifier (NID).
type NodeID uint64

const (
	UnspecifiedNodeID    = (NodeID)(0x0000000000000000)
	minOperationalNodeID = (NodeID)(0x0000000000000001)
	maxOperationalNodeID = (NodeID)(0xFFFFFFFEFFFFFFFF)
)

// IsUnspecified returns true if the NodeID is the unspecified NodeID.
func (nid NodeID) IsUnspecified() bool {
	return nid == UnspecifiedNodeID
}

// IsOperational returns true if the NodeID is an operational NodeID.
func (nid NodeID) IsOperational() bool {
	return nid >= minOperationalNodeID && nid <= maxOperationalNodeID
}

// String returns the string representation of the NodeID.
func (nid NodeID) String() string {
	return fmt.Sprintf("%d", uint64(nid))
}
