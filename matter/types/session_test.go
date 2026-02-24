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
	"testing"
)

func TestSessionID(t *testing.T) {
	// Test that NewSessionID returns different values on multiple calls (statistically likely)
	id1 := NewSessionID()
	id2 := NewSessionID()
	if id1 == id2 {
		t.Logf("Warning: NewSessionID generated duplicate IDs: %v", id1)
	}

	// Test that NewSessionIDExcept returns a different ID than the given one
	for range 10 {
		orig := NewSessionID()
		newID := NewSessionIDExcept(orig)
		if newID == orig {
			t.Errorf("NewSessionIDExcept returned the same ID: %v", orig)
		}
	}

	// Test that NewSessionIDExcept returns a valid SessionID
	orig := SessionID(0x1234)
	newID := NewSessionIDExcept(orig)
	if newID == orig {
		t.Errorf("NewSessionIDExcept returned the same ID as input: %v", orig)
	}
}
