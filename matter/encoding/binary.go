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

// IntegerToByte converts a specified integer to bytes.
func IntegerToByte(v uint, b []byte) {
	byteSize := len(b)
	for n := 0; n < byteSize; n++ {
		idx := ((byteSize - 1) - n)
		b[idx] = byte((v >> (uint(n) * 8)) & 0xFF)
	}
}

// ByteToInteger converts specified bytes to a integer.
func ByteToInteger(b []byte) uint {
	var v uint
	byteSize := len(b)
	for n := 0; n < byteSize; n++ {
		idx := ((byteSize - 1) - n)
		v += (uint(b[idx]) << (uint(n) * 8))
	}
	return v
}
