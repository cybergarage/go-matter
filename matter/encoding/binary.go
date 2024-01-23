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

// IntegerToBytes converts a specified integer to bytes.
func IntegerToBytes(v uint, b []byte) {
	byteSize := len(b)
	for n := 0; n < byteSize; n++ {
		idx := ((byteSize - 1) - n)
		b[idx] = byte((v >> (uint(n) * 8)) & 0xFF)
	}
}

// BytesToInteger converts specified bytes to a integer.
func BytesToInteger(b []byte) uint {
	var v uint
	byteSize := len(b)
	for n := 0; n < byteSize; n++ {
		idx := ((byteSize - 1) - n)
		v += (uint(b[idx]) << (uint(n) * 8))
	}
	return v
}

// Uint8ToBytes converts a specified integer to bytes.
func Uint8ToBytes(v uint8, b *[1]byte) {
	b[0] = byte(v)
}

// BytesToUint8 converts specified bytes to a integer.
func BytesToUint8(b [1]byte) uint8 {
	return uint8(b[0])
}

// Uint16ToBytes converts a specified integer to bytes.
func Uint16ToBytes(v uint16, b *[2]byte) {
	b[0] = byte(v >> 8)
	b[1] = byte(v & 0xff)
}

// Byte2ToUint16 converts specified bytes to a integer.
func Byte2ToUint16(b [2]byte) uint16 {
	return uint16(b[0])<<8 | uint16(b[1])
}

// Uint32ToBytes converts a specified integer to bytes.
func Uint32ToBytes(v uint32, b *[4]byte) {
	b[0] = byte(v >> 24)
	b[1] = byte(v >> 16)
	b[2] = byte(v >> 8)
	b[3] = byte(v & 0xff)
}

// BytesToUint32 converts specified bytes to a integer.
func BytesToUint32(b [4]byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// Uint64ToBytes converts a specified integer to bytes.
func Uint64ToBytes(v uint64, b *[8]byte) {
	b[0] = byte(v >> 56)
	b[1] = byte(v >> 48)
	b[2] = byte(v >> 40)
	b[3] = byte(v >> 32)
	b[4] = byte(v >> 24)
	b[5] = byte(v >> 16)
	b[6] = byte(v >> 8)
	b[7] = byte(v & 0xff)
}

// BytesToUint64 converts specified bytes to a integer.
func BytesToUint64(b [8]byte) uint64 {
	return uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 | uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
}
