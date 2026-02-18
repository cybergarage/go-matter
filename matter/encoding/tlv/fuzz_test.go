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

package tlv

import (
	"testing"
)

func FuzzDecodeEncode(f *testing.F) {
	enc := NewEncoder()
	_ = enc.PutUnsigned(ContextTag(1), 1)
	enc.StartArray(ContextTag(2))
	_ = enc.PutUnsigned(AnonymousTag(), 2)
	enc.EndContainer()
	enc.MustEndAll()
	f.Add(enc.Bytes())

	f.Fuzz(func(t *testing.T, data []byte) {
		dec := NewDecoderWithBytes(data)
		for dec.Next() {
			_ = dec.Element()
		}
	})
}
