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

package mrp

import (
	"github.com/cybergarage/go-matter/matter/encoding/message"
)

// MessageCounter tracks outbound message counters for a session.
// 4.4.1.4. Message Counter (32 bits).
type MessageCounter = message.MessageCounter

// NewMessageCounter creates a new message counter starting from 0.
func NewMessageCounter() MessageCounter {
	return message.NewMessageCounter()
}
