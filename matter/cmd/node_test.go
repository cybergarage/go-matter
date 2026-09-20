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

import "testing"

func TestParseUint64(t *testing.T) {
	tests := []struct {
		in      string
		want    uint64
		wantErr bool
	}{
		{in: "1234", want: 1234},
		{in: "0", want: 0},
		{in: "0x11", want: 0x11},
		{in: "0X11", want: 0x11},
		{in: "0xDEAD", want: 0xDEAD},
		// A leading zero must NOT be treated as octal (chip-tool doesn't
		// either) — "0123" must parse as decimal 123, not octal 83.
		{in: "0123", want: 123},
		{in: "", wantErr: true},
		{in: "not-a-number", wantErr: true},
		{in: "0xZZZZ", wantErr: true},
		{in: "18446744073709551616", wantErr: true}, // overflows uint64
	}
	for _, tt := range tests {
		got, err := parseUint64(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("parseUint64(%q) error = nil, want non-nil", tt.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseUint64(%q) error = %v, want nil", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("parseUint64(%q) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

func TestParseEndpointID(t *testing.T) {
	if v, err := parseEndpointID("1"); err != nil || v != 1 {
		t.Errorf("parseEndpointID(%q) = %v, %v; want 1, nil", "1", v, err)
	}
	if v, err := parseEndpointID("0xFFFF"); err != nil || v != 0xFFFF {
		t.Errorf("parseEndpointID(%q) = %v, %v; want 0xFFFF, nil", "0xFFFF", v, err)
	}
	if _, err := parseEndpointID("0x10000"); err == nil {
		t.Error("parseEndpointID(\"0x10000\") error = nil, want out-of-range error")
	}
	if _, err := parseEndpointID("bogus"); err == nil {
		t.Error("parseEndpointID(\"bogus\") error = nil, want non-nil")
	}
}

func TestParseClusterID(t *testing.T) {
	if v, err := parseClusterID("0x001D"); err != nil || v != 0x001D {
		t.Errorf("parseClusterID(%q) = %v, %v; want 0x1D, nil", "0x001D", v, err)
	}
	if _, err := parseClusterID("0x100000000"); err == nil {
		t.Error("parseClusterID(\"0x100000000\") error = nil, want out-of-range error")
	}
}

func TestParseAttributeID(t *testing.T) {
	if v, err := parseAttributeID("0"); err != nil || v != 0 {
		t.Errorf("parseAttributeID(%q) = %v, %v; want 0, nil", "0", v, err)
	}
	if _, err := parseAttributeID("0x100000000"); err == nil {
		t.Error("parseAttributeID(\"0x100000000\") error = nil, want out-of-range error")
	}
}

func TestParseCommandID(t *testing.T) {
	if v, err := parseCommandID("0x02"); err != nil || v != 2 {
		t.Errorf("parseCommandID(%q) = %v, %v; want 2, nil", "0x02", v, err)
	}
	if _, err := parseCommandID("0x100000000"); err == nil {
		t.Error("parseCommandID(\"0x100000000\") error = nil, want out-of-range error")
	}
}
