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

import (
	"fmt"
)

// ContextNumber represents a context-specific tag number.
type ContextNumber uint8

// NewContextNumberFromTag returns a context number from the given tag.
func NewContextNumberFromTag(t Tag) (ContextNumber, bool) {
	switch v := t.(type) {
	case tagContext:
		return ContextNumber(v.number), true
	default:
		return 0, false
	}
}

// ContextTag represents a context-specific tag with a 1-byte number.
type ContextTag interface {
	Tag
	// ContextNumber returns the context number (0-255).
	ContextNumber() ContextNumber
}

// tagContext is a context-specific tag with a 1-byte number.
type tagContext struct {
	number uint8
}

// NewContextTag constructs a context-specific tag with the given 1-byte number.
func NewContextTag(num uint8) ContextTag { return tagContext{number: num} }

// Control returns TagCtlContext.
func (t tagContext) Control() TagControl { return TagContext }

// Bytes returns the single context tag byte.
func (t tagContext) Bytes() []byte { return []byte{t.number} }

// String returns a descriptive string for the context tag.
func (t tagContext) String() string { return fmt.Sprintf("Context(%d)", t.number) }

// ContextNumber returns the context number.
func (t tagContext) ContextNumber() ContextNumber { return ContextNumber(t.number) }
