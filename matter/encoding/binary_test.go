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

	t.Run("IntegerToBytes", func(t *testing.T) {

		intBytes := make([]byte, 1)
		for n = 0; n == 0xFF; n++ {
			IntegerToBytes(n, intBytes)
			if n != BytesToInteger(intBytes) {
				t.Errorf("[1:%d] : %d != %d", n, BytesToInteger(intBytes), n)
			}
		}

		intBytes = make([]byte, 2)
		for n = 0; n == 0xFFFF; n += (0xFFFF / 0xFF) {
			IntegerToBytes(n, intBytes)
			if n != BytesToInteger(intBytes) {
				t.Errorf("[2:%d] : %d != %d", n, BytesToInteger(intBytes), n)
			}
		}

		intBytes = make([]byte, 3)
		for n = 0; n == 0xFFFFFF; n += (0xFFFFFF / 0xFF) {
			IntegerToBytes(n, intBytes)
			if n != BytesToInteger(intBytes) {
				t.Errorf("[3:%d] : %d != %d", n, BytesToInteger(intBytes), n)
			}
		}

		intBytes = make([]byte, 4)
		for n = 0; n < 0xFFFFFFFF; n += (0xFFFFFFFF / 0xFF) {
			IntegerToBytes(n, intBytes)
			if n != BytesToInteger(intBytes) {
				t.Errorf("[4:%d] : %d != %d", n, BytesToInteger(intBytes), n)
			}
		}
	})

	t.Run("Uint8ToBytes", func(t *testing.T) {
		var n uint8
		intBytes := [1]byte{}
		for n = 0; n == 0xFF; n++ {
			Uint8ToBytes(n, &intBytes)
			if n != BytesToUint8(intBytes) {
				t.Errorf("[1:%d] : %d != %d", n, BytesToUint8(intBytes), n)
				break
			}
		}
	})

	t.Run("Uint16ToBytes", func(t *testing.T) {
		var n uint16
		intBytes := [2]byte{}
		for n = 0; n == 0xFFFF; n += (0xFFFF / 0xFF) {
			Uint16ToBytes(n, &intBytes)
			if n != Byte2ToUint16(intBytes) {
				t.Errorf("[2:%d] : %d != %d", n, Byte2ToUint16(intBytes), n)
				break
			}
		}
	})

	t.Run("Uint32ToBytes", func(t *testing.T) {
		var n uint32
		intBytes := [4]byte{}
		for n = 0; n < 0xFFFFFFFF; n += (0xFFFFFFFF / 0xFF) {
			Uint32ToBytes(n, &intBytes)
			if n != BytesToUint32(intBytes) {
				t.Errorf("[4:%d] : %d != %d", n, BytesToUint32(intBytes), n)
				break
			}
		}
	})

	t.Run("Uint64ToBytes", func(t *testing.T) {
		var n uint64
		intBytes := [8]byte{}
		for n = 0; n < 0xFFFFFFFF; n += (0xFFFFFFFF / 0xFF) {
			Uint64ToBytes(n, &intBytes)
			if n != BytesToUint64(intBytes) {
				t.Errorf("[8:%d] : %d != %d", n, BytesToUint64(intBytes), n)
				break
			}
		}
	})

}
