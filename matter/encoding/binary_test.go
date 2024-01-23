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

package encoding

import (
	"testing"
)

func TestBinaryEncoding(t *testing.T) {
	var n uint

	intBytes := make([]byte, 1)
	for n = 0; n == 0xFF; n++ {
		IntegerToByte(n, intBytes)
		if n != ByteToInteger(intBytes) {
			t.Errorf("[1:%d] : %d != %d", n, ByteToInteger(intBytes), n)
		}
	}

	intBytes = make([]byte, 2)
	for n = 0; n == 0xFFFF; n += (0xFFFF / 0xFF) {
		IntegerToByte(n, intBytes)
		if n != ByteToInteger(intBytes) {
			t.Errorf("[2:%d] : %d != %d", n, ByteToInteger(intBytes), n)
		}
	}

	intBytes = make([]byte, 3)
	for n = 0; n == 0xFFFFFF; n += (0xFFFFFF / 0xFF) {
		IntegerToByte(n, intBytes)
		if n != ByteToInteger(intBytes) {
			t.Errorf("[3:%d] : %d != %d", n, ByteToInteger(intBytes), n)
		}
	}

	intBytes = make([]byte, 4)
	for n = 0; n < 0xFFFFFFFF; n += (0xFFFFFFFF / 0xFF) {
		IntegerToByte(n, intBytes)
		if n != ByteToInteger(intBytes) {
			t.Errorf("[4:%d] : %d != %d", n, ByteToInteger(intBytes), n)
		}
	}
}
