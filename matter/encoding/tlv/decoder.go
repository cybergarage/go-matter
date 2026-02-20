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

// Decoder provides a streaming interface for reading TLV elements
// from an in-memory byte slice. EndOfContainer markers are consumed
// internally and not surfaced.
type Decoder interface {
	// More returns true if there is more data to decode (not EOF).
	More() bool
	// Next advances to the next element; returns false on EOF or error.
	// After false, check Error() to distinguish normal EOF vs error.
	Next() bool
	// Element returns the most recently decoded element. It is valid
	// only if the preceding Next() returned true.
	Element() Element
	// Error returns the first error encountered (if any).
	Error() error
}
