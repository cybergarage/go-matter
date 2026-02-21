// Copyright (C) 2025 The go-matter Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pake

// Pake1 represents the PASE PAKE1 message, which includes the initiator random, responder random, and other parameters.
type Pake1 interface {
	Pake1Helper
	// pA returns the initiator random value from the Pake1 message.
	pA() []byte
}

// Pake1Helper provides helper methods for working with Pake1 messages, such as mapping the message to a generic map and converting it to a string representation.
type Pake1Helper interface {
	Map() map[string]any
	String() string
}
