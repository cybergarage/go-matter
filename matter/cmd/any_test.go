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
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/cybergarage/go-matter/matter/datamodel/command"
	"github.com/cybergarage/go-matter/matter/protocol/im"
)

func TestInvokeFieldsFromTheCatalog(t *testing.T) {
	// Level Control (0x0008) MoveToLevel (0x00).
	fields, err := invokeFields(0x0008, 0x00, "", []string{"Level=127", "TransitionTime=10", "OptionsMask=0", "OptionsOverride=0"})
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(fields); got != "350124007f24010a24020024030018" {
		t.Fatalf("fields = %s", got)
	}
	// Names in another case, an enumeration name and null.
	fields, err = invokeFields(0x0008, 0x01, "", []string{"movemode=Down", "rate=null", "optionsmask=ExecuteIfOff", "optionsoverride=0x1"})
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(fields); got != "3501240001340124020124030118" {
		t.Fatalf("fields = %s", got)
	}
}

func TestInvokeFieldsRawBlobAndNone(t *testing.T) {
	fields, err := invokeFields(0x0006, 0x01, "", nil)
	if err != nil || fields != nil {
		t.Fatalf("no fields: %x, %v", fields, err)
	}
	fields, err = invokeFields(0x0006, 0x40, "0x350118", nil)
	if err != nil || hex.EncodeToString(fields) != "350118" {
		t.Fatalf("raw blob: %x, %v", fields, err)
	}
	if _, err := invokeFields(0x0006, 0x40, "zz", nil); err == nil {
		t.Fatal("malformed raw blob accepted")
	}
}

func TestInvokeFieldsErrors(t *testing.T) {
	tests := []struct {
		name    string
		cluster im.ClusterID
		command im.CommandID
		raw     string
		fields  []string
		is      error
		message string
	}{
		{"both flags", 0x0008, 0, "350118", []string{"Level=1"}, nil, "cannot be used together"},
		{"cluster outside the catalog", 0x0003, 0, "", []string{"IdentifyTime=5"}, command.ErrUnknownCommand, ""},
		{"no equals sign", 0x0008, 0, "", []string{"Level"}, nil, "expected name=value"},
		{"unknown field", 0x0008, 0, "", []string{"Brightness=1"}, command.ErrUnknownField, ""},
		{"field given twice", 0x0008, 0, "", []string{"Level=1", "level=2"}, nil, "more than once"},
		{"missing field", 0x0008, 0, "", []string{"Level=1"}, command.ErrMissingField, ""},
		{"out of range", 0x0008, 0, "", []string{"Level=255", "TransitionTime=0", "OptionsMask=0", "OptionsOverride=0"}, command.ErrInvalidValue, ""},
		// Door Lock (0x0101) LockDoor (0x00) has to be a timed invoke.
		{"timed command", 0x0101, 0, "", []string{"PINCode=31323334"}, nil, "timed invoke"},
	}
	for _, tt := range tests {
		_, err := invokeFields(tt.cluster, tt.command, tt.raw, tt.fields)
		switch {
		case err == nil:
			t.Errorf("%s: accepted", tt.name)
		case tt.is != nil && !errors.Is(err, tt.is):
			t.Errorf("%s: %v", tt.name, err)
		case tt.message != "" && !strings.Contains(err.Error(), tt.message):
			t.Errorf("%s: %v", tt.name, err)
		}
	}
}
