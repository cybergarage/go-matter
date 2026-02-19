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

func TestVersion(t *testing.T) {
	tests := []struct {
		version  Version
		expected struct {
			major int
			minor int
			dot   int
		}
	}{
		// 11.1.5.22. SpecificationVersion Attribute
		{Version(0x01000000), struct{ major, minor, dot int }{1, 0, 0}},
		{Version(0x01030000), struct{ major, minor, dot int }{1, 3, 0}},
	}

	for _, test := range tests {
		t.Run(test.version.String(), func(t *testing.T) {
			if test.version.Major() != test.expected.major {
				t.Errorf("Unexpected major version: got %d, want %d", test.version.Major(), test.expected.major)
			}
			if test.version.Minor() != test.expected.minor {
				t.Errorf("Unexpected minor version: got %d, want %d", test.version.Minor(), test.expected.minor)
			}
			if test.version.Dot() != test.expected.dot {
				t.Errorf("Unexpected dot version: got %d, want %d", test.version.Dot(), test.expected.dot)
			}
		})
	}
}
