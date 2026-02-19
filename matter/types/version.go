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

package types

import (
	"fmt"
)

// Version represents the version of any attributes.
// 11.1.5.22. SpecificationVersion Attribute.
type Version uint32

// NewVersion creates a Version from major, minor, and dot components.
func NewVersion(major, minor, dot int) Version {
	return Version((major&0xFF)<<24 | (minor&0xFF)<<16 | (dot&0xFF)<<8)
}

// Major returns the major version component (bits 31..24).
func (v Version) Major() int {
	return int((v >> 24) & 0xFF)
}

// Minor returns the minor version component (bits 23..16).
func (v Version) Minor() int {
	return int((v >> 16) & 0xFF)
}

// Dot returns the dot version component (bits 15..8).
func (v Version) Dot() int {
	return int((v >> 8) & 0xFF)
}

// String returns the version in "major.minor.dot" format.
func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major(), v.Minor(), v.Dot())
}
