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

import (
	"testing"
)

func TestExchangeID(t *testing.T) {
	t.Run("FuzzNewFirstExchangeID", func(t *testing.T) {
		for range 1000 {
			id := NewFirstExchangeID()
			if id < minExchangeID || id > maxExchangeID {
				t.Errorf("NewFirstExchangeID() returned out of range value: %d", id)
			}
			if id == 0 {
				t.Errorf("NewFirstExchangeID() returned reserved value: %d", id)
			}
			nextID := id.Next()
			if nextID.Compare(id) <= 0 {
				t.Errorf("ExchangeID.Next() did not change value for %d", id)
			}
		}
	})

	t.Run("TestExchangeIDNext", func(t *testing.T) {
		id := ExchangeID(maxExchangeID)
		nextID := id.Next()
		if nextID != overflowExchangeID {
			t.Errorf("Expected Next() to return %d, got %d", overflowExchangeID, nextID)
		}
		if nextID.Compare(id) <= 0 {
			t.Errorf("Expected Next() to return a value greater than %d, got %d", id, nextID)
		}
	})
}
