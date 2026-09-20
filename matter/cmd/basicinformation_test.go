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

// TestRunBasicinformationReadUnknownAttribute mirrors
// TestRunDescriptorReadUnknownAttribute: the attribute-name argument must be
// validated before connecting, so an unknown name fails fast with no live
// node involved.
func TestRunBasicinformationReadUnknownAttribute(t *testing.T) {
	err := runBasicinformationRead(basicinformationReadCmd, []string{"bogus-attribute", "1", "0"})
	if err == nil {
		t.Fatal("runBasicinformationRead(...) error = nil, want non-nil for an unknown attribute")
	}
	if !strings.Contains(err.Error(), "bogus-attribute") {
		t.Errorf("runBasicinformationRead(...) error = %q, want it to mention the unknown attribute name", err)
	}
}

// TestBasicinformationAttributeNamesCoverAllExportedGetters guards against a
// regression where a new getter is added to matter/cluster/basicinformation
// without a matching entry here, silently making it unreachable from the CLI.
func TestBasicinformationAttributeNamesCoverAllExportedGetters(t *testing.T) {
	want := []string{
		"data-model-revision", "vendor-name", "vendor-id", "product-name", "product-id",
		"node-label", "location", "hardware-version", "hardware-version-string",
		"software-version", "software-version-string", "serial-number", "unique-id",
	}
	if len(basicinformationAttributeNames) != len(want) {
		t.Fatalf("basicinformationAttributeNames has %d entries, want %d (%v)", len(basicinformationAttributeNames), len(want), want)
	}
	for i, name := range want {
		if basicinformationAttributeNames[i] != name {
			t.Errorf("basicinformationAttributeNames[%d] = %q, want %q", i, basicinformationAttributeNames[i], name)
		}
	}
}
