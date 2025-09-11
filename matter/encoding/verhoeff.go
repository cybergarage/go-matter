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

package encoding

// verhoeffTables contains the multiplication (d), permutation (p), and inverse (inv) tables for Verhoeff algorithm.
var verhoeffTables = struct {
	d   [][]int
	p   [][]int
	inv []int
}{
	d: [][]int{
		{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
		{1, 2, 3, 4, 0, 6, 7, 8, 9, 5},
		{2, 3, 4, 0, 1, 7, 8, 9, 5, 6},
		{3, 4, 0, 1, 2, 8, 9, 5, 6, 7},
		{4, 0, 1, 2, 3, 9, 5, 6, 7, 8},
		{5, 9, 8, 7, 6, 0, 4, 3, 2, 1},
		{6, 5, 9, 8, 7, 1, 0, 4, 3, 2},
		{7, 6, 5, 9, 8, 2, 1, 0, 4, 3},
		{8, 7, 6, 5, 9, 3, 2, 1, 0, 4},
		{9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
	},
	p: [][]int{
		{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
		{1, 5, 7, 6, 2, 8, 3, 0, 9, 4},
		{5, 8, 0, 3, 7, 9, 6, 1, 4, 2},
		{8, 9, 1, 6, 0, 4, 3, 5, 2, 7},
		{9, 4, 5, 3, 1, 2, 6, 8, 7, 0},
		{4, 2, 8, 6, 5, 7, 3, 9, 0, 1},
		{2, 7, 9, 3, 8, 0, 6, 4, 1, 5},
		{7, 0, 4, 6, 9, 1, 3, 2, 5, 8},
	},
	inv: []int{0, 4, 3, 2, 1, 5, 6, 7, 8, 9},
}

// generateVerhoeffCheck computes the Verhoeff checksum digit for a numeric string (no spaces).
func generateVerhoeffCheck(numStr string) byte {
	// Compute the Verhoeff checksum digit by processing the number with an extra 0 at the end.
	c := 0
	// Append a '0' (placeholder for check digit) and process from rightmost digit
	for i, r := range reverseString(numStr + "0") {
		digit := int(r - '0')
		c = verhoeffTables.d[c][verhoeffTables.p[i%8][digit]]
	}
	checkDigit := verhoeffTables.inv[c]
	return byte('0' + checkDigit)
}

// validateVerhoeffCheck verifies that a numeric string (including the check digit) has a valid Verhoeff checksum.
func validateVerhoeffCheck(code string) bool {
	c := 0
	for i, r := range reverseString(code) {
		digit := int(r - '0')
		c = verhoeffTables.d[c][verhoeffTables.p[i%8][digit]]
	}
	return c == 0
}

// reverseString returns the reverse of the input string.
func reverseString(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}
