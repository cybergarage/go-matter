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
	"github.com/cybergarage/go-matter/matter/crypto"
	"github.com/cybergarage/go-safecast/safecast"
)

// NewNodeIDFrom creates a new NodeID from the given value.
func NewNodeIDFrom(v any) (NodeID, error) {
	var vid uint64
	if err := safecast.ToUint64(v, &vid); err != nil {
		return 0, err
	}
	return NodeID(vid), nil
}

// NewRandomNodeID generates a new random NodeID in the range [min, max].
func NewRandomNodeID(min NodeID, max NodeID) NodeID {
	if max <= min {
		return min
	}
	b := crypto.CryptoDRBG(4)
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	return min + NodeID(uint64(v)%uint64(max-min))
}

// NewOperationalNodeID generates a new random operational NodeID.
func NewOperationalNodeID() NodeID {
	return NewRandomNodeID(minOperationalNodeID, maxOperationalNodeID)
}
