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

package pbkdf

import (
	"hash"
)

// PBKDFParamRequest/Response fields are defined by the Matter specification using
// context-specific tag numbers.
const (
	pbkdfTagIterations = 1
	pbkdfTagSalt       = 2
)

type Params struct {
	Password []byte
	Salt     []byte
	Iter     int
	KeyLen   int
	Hash     func() hash.Hash
}
