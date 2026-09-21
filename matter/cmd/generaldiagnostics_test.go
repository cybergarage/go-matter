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

// TestRunGeneraldiagnosticsReadUnknownAttribute guards against a
// regression where the attribute-name argument wasn't validated before
// connecting — see descriptor_test.go's matching test for why this must
// fail before ever reaching connectNode.
func TestRunGeneraldiagnosticsReadUnknownAttribute(t *testing.T) {
	err := runGeneraldiagnosticsRead(generaldiagnosticsReadCmd, []string{"bogus-attribute", "1", "0"})
	if err == nil {
		t.Fatal("runGeneraldiagnosticsRead(...) error = nil, want non-nil for an unknown attribute")
	}
	if !strings.Contains(err.Error(), "bogus-attribute") {
		t.Errorf("runGeneraldiagnosticsRead(...) error = %q, want it to mention the unknown attribute name", err)
	}
}
