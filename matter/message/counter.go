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

package message

// 4.4.1.5. Message Counter (32 bits)
// Counter represents a message counter.
type Counter uint32

// NewCounter returns a new counter.
func NewCounter() Counter {
	// 4.5.1.1. Message Counter Initialization
	// TODO: All message counters SHALL be initialized with a random value
	// using the Crypto_DRBG(len = 28) +1 primitive.
	return 1
}
