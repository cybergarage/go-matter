// Copyright (C) 2026 The go-matter Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package session

import (
	"sync"

	"github.com/cybergarage/go-matter/matter/encoding/message"
)

// counterWindowSize is MSG_COUNTER_WINDOW_SIZE.
// 4.6.5.3. Message Counter Window.
const counterWindowSize = 32

// counterWindow detects the duplicates among the messages a secure unicast
// session receives (4.6.5.3.1): it keeps the largest counter received and
// which of the counterWindowSize counters below it were received. A
// counter at or below the window is a duplicate, as an encrypted unicast
// session's counters only grow.
type counterWindow struct {
	mutex  sync.Mutex
	synced bool
	max    uint32
	bitmap uint32 // bit i: max-1-i was received
}

// accept records counter, and reports whether it is new.
func (w *counterWindow) accept(counter message.MessageCounter) bool {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	c := uint32(counter)
	if !w.synced {
		w.synced = true
		w.max = c
		w.bitmap = 0
		return true
	}
	if c > w.max {
		shift := c - w.max
		if shift > counterWindowSize {
			w.bitmap = 0
		} else {
			w.bitmap = w.bitmap<<shift | 1<<(shift-1)
		}
		w.max = c
		return true
	}
	if c == w.max {
		return false
	}
	offset := w.max - c - 1
	if offset >= counterWindowSize {
		return false
	}
	if w.bitmap&(1<<offset) != 0 {
		return false
	}
	w.bitmap |= 1 << offset
	return true
}
