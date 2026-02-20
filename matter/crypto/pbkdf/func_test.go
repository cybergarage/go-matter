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
	"crypto/sha256"
	"testing"
)

func TestCryptoPBKDF(t *testing.T) {
	p := NewParams(
		WithParamsPassword([]byte("password")),
		WithParamsSalt([]byte("salt")),
		WithParamsIterations(1000),
		WithParamsKeyLength(32),
		WithParamsHash(sha256.New),
	)
	_, err := CryptoPBKDF(p)
	if err != nil {
		t.Fatalf("CryptoPBKDF failed: %v", err)
	}
}
