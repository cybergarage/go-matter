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

func TestPasscode(t *testing.T) {
	tests := []struct {
		passcode Passcode
		bytes    string
	}{
		// 3.10. Password-Authenticated Key Exchange (PAKE)
		{Passcode(18924017), "f1:c1:20:01"},
		{Passcode(00000005), "05:00:00:00"},
	}

	for _, test := range tests {
		s := string(test.passcode.Bytes())
		if s != test.bytes {
			t.Errorf("Unexpected passcode bytes: got %v, want %v", s, test.bytes)
		}
	}
}
