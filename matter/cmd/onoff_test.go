// Copyright (C) 2026 The go-matter Authors. All rights reserved.
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

package cmd

import (
	"strings"
	"testing"
)

// TestRunOnOffReadUnknownAttribute mirrors the descriptor/basicinformation
// unknown-attribute tests: the attribute-name argument must be validated
// before connecting, so an unknown name fails fast with no live node
// involved.
func TestRunOnOffReadUnknownAttribute(t *testing.T) {
	err := runOnOffRead(onoffReadCmd, []string{"bogus-attribute", "1", "0"})
	if err == nil {
		t.Fatal("runOnOffRead(...) error = nil, want non-nil for an unknown attribute")
	}
	if !strings.Contains(err.Error(), "bogus-attribute") {
		t.Errorf("runOnOffRead(...) error = %q, want it to mention the unknown attribute name", err)
	}
}
