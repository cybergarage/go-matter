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

// TestRunDescriptorReadUnknownAttribute guards against a regression where
// the attribute-name argument wasn't validated before connecting — an
// unknown name should fail fast, with no SharedCommissioner()/live node
// involved at all (SharedCommissioner() is nil in this test's process, so a
// call reaching connectNode would panic instead of returning a clean error).
func TestRunDescriptorReadUnknownAttribute(t *testing.T) {
	err := runDescriptorRead(descriptorReadCmd, []string{"bogus-attribute", "1", "0"})
	if err == nil {
		t.Fatal("runDescriptorRead(...) error = nil, want non-nil for an unknown attribute")
	}
	if !strings.Contains(err.Error(), "bogus-attribute") {
		t.Errorf("runDescriptorRead(...) error = %q, want it to mention the unknown attribute name", err)
	}
}
