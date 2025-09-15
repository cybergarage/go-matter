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

func TestDiscriminator(t *testing.T) {
	tests := []struct {
		v1       Discriminator
		v2       any
		expected bool
	}{
		{Discriminator(3136), Discriminator(3136), true},
		{Discriminator(3136), Discriminator(3072), true},
		{Discriminator(3136), uint16(3136), true},
		{Discriminator(3136), uint16(3072), true},
		{Discriminator(3136), int(3136), true},
		{Discriminator(3136), int(3072), true},
		{Discriminator(3136), uint16(4072), false},
		{Discriminator(3136), int(4072), false},
	}

	for _, test := range tests {
		if test.v1.Equal(test.v2) != test.expected {
			t.Errorf("Unexpected result for %v and %v: got %v, want %v",
				test.v1, test.v2, test.v1.Equal(test.v2), test.expected)
		}
	}
}
