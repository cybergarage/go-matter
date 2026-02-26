// Copyright (C) 2025 The go-matter Authors. All rights reserved.
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

package crypto

import (
	"testing"
)

func TestCryptoPBKDF(t *testing.T) {
	passwords := [][]byte{
		[]byte("password"),
		[]byte("longerpassword123"),
		[]byte(""),
	}
	salts := [][]byte{
		[]byte("salt"),
		[]byte("diffsalt"),
		[]byte(""),
	}
	lengths := []int{1, 16, 32, 64, 128, 256}
	iterations := 1000

	for _, pw := range passwords {
		for _, salt := range salts {
			for _, l := range lengths {
				out, err := CryptoPBKDF(pw, salt, iterations, l)
				if err != nil {
					t.Errorf("CryptoPBKDF(%q, %q, %d, %d) returned error: %v", pw, salt, iterations, l, err)
					continue
				}
				if len(out) != l {
					t.Errorf("CryptoPBKDF(%q, %q, %d, %d) returned length %d, want %d", pw, salt, iterations, l, len(out), l)
				}
			}
		}
	}
}
