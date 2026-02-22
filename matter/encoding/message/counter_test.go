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
	"testing"
)

func TestMessageCounter(t *testing.T) {
	// Test that the MessageCounter increments correctly and wraps around at the maximum value.
	mc := MessageCounter(0)
	for range 10 {
		next := mc.Next()
		if next < mc {
			t.Errorf("MessageCounter overflowed: got %d, expected greater than %d", next, mc)
		}
		mc = next
	}

	// Test overflow behavior
	mc = MessageCounter(^uint32(0)) // max uint32
	next := mc.Next()
	if next != 0 {
		t.Errorf("MessageCounter did not wrap around: got %d, expected 0", next)
	}

	// Test NewMessageCounter starts at 0
	mc = NewMessageCounter()
	if mc != 0 {
		t.Errorf("NewMessageCounter did not start at 0: got %d", mc)
	}

	// Test incrementing from a random value
	mc = MessageCounter(12345)
	next = mc.Next()
	if next != 12346 {
		t.Errorf("MessageCounter did not increment correctly: got %d, expected 12346", next)
	}
}
