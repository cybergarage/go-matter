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

package tlv

// ContextNumber represents a context-specific tag number.
type ContextNumber uint8

// NewContextNumberFromTag returns a context number from the given tag.
func NewContextNumberFromTag(t Tag) (ContextNumber, bool) {
	switch v := t.(type) {
	case tagContext:
		return ContextNumber(v.Num), true
	default:
		return 0, false
	}
}
