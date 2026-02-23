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

package types

import (
	"testing"
)

func TestNodeID(t *testing.T) {
	id := NodeID(12345)
	if id != 12345 {
		t.Errorf("Expected NodeID to be 12345, got %v", id)
	}

	// Test UnspecifiedNodeID constant
	if UnspecifiedNodeID != NodeID(0x0000000000000000) {
		t.Errorf("Expected UnspecifiedNodeID to be 0, got %v", UnspecifiedNodeID)
	}

	// Test NewOperationalNodeID returns a valid NodeID
	randomID := NewOperationalNodeID()
	if !randomID.IsOperational() {
		t.Errorf("NewOperationalNodeID returned out of range value: got %v, expected between %v and %v", randomID, minOperationalNodeID, maxOperationalNodeID)
	}
}
