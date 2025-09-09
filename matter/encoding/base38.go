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

import (
	"errors"
)

const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-."

var (
	rev = func() [256]int {
		var r [256]int
		for i := range r {
			r[i] = -1
		}
		for i := range len(alphabet) {
			r[alphabet[i]] = i
		}
		return r
	}()
)

// EncodeBase38 encodes raw bytes using Matter's Base-38 scheme.
//
// Spec summary:
// - Process as little-endian chunks from the byte slice head.
// - For every 3 bytes -> one 24-bit unsigned integer -> 5 base-38 chars (LS char first).
// - Remaining 2 bytes -> one 16-bit unsigned integer -> 4 chars (LS first).
// - Remaining 1 byte  -> 2 chars (LS first).
func EncodeBase38(src []byte) string {
	n := len(src)
	if n == 0 {
		return ""
	}
	out := make([]byte, 0, (n*8+4)/5) // rough upper bound

	i := 0
	for i+3 <= n {
		u := uint32(src[i]) | uint32(src[i+1])<<8 | uint32(src[i+2])<<16
		for range 5 {
			out = append(out, alphabet[u%38])
			u /= 38
		}
		i += 3
	}
	rem := n - i
	switch rem {
	case 2:
		u := uint32(src[i]) | uint32(src[i+1])<<8
		for range 4 {
			out = append(out, alphabet[u%38])
			u /= 38
		}
	case 1:
		u := uint32(src[i])
		for range 2 {
			out = append(out, alphabet[u%38])
			u /= 38
		}
	}
	return string(out)
}

// DecodeBase38 decodes a Matter Base-38 string back to raw bytes.
// It accepts only the 38-char alphabet defined by the spec.
func DecodeBase38(s string) ([]byte, error) {
	if len(s) == 0 {
		return []byte{}, nil
	}
	// Consume in groups corresponding to the encoder's outputs:
	// 5 chars -> 3 bytes, 4 chars -> 2 bytes, 2 chars -> 1 byte.
	// Any leftover lengths are invalid for a proper packed payload.
	out := make([]byte, 0, len(s)) // rough
	i := 0
	for i+5 <= len(s) {
		var u uint32
		m := uint32(1)
		for j := range 5 {
			c := int(s[i+j])
			val := -1
			if c < 256 {
				val = rev[c]
			}
			if val < 0 {
				return nil, errors.New("invalid base38 character")
			}
			u += uint32(val) * m
			m *= 38
		}
		out = append(out, byte(u&0xFF), byte((u>>8)&0xFF), byte((u>>16)&0xFF))
		i += 5
	}
	rest := len(s) - i
	switch rest {
	case 0:
		// ok
	case 4:
		var u uint32
		m := uint32(1)
		for j := range 4 {
			c := int(s[i+j])
			val := -1
			if c < 256 {
				val = rev[c]
			}
			if val < 0 {
				return nil, errors.New("invalid base38 character")
			}
			u += uint32(val) * m
			m *= 38
		}
		out = append(out, byte(u&0xFF), byte((u>>8)&0xFF))
	case 2:
		var u uint32
		m := uint32(1)
		for j := range 2 {
			c := int(s[i+j])
			val := -1
			if c < 256 {
				val = rev[c]
			}
			if val < 0 {
				return nil, errors.New("invalid base38 character")
			}
			u += uint32(val) * m
			m *= 38
		}
		out = append(out, byte(u&0xFF))
	default:
		return nil, errors.New("invalid base38 length")
	}
	return out, nil
}
