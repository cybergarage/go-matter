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
	"io"
	"os"
	"strings"
	"testing"

	"github.com/cybergarage/go-matter/matter/encoding/tlv"
)

// buildElement encodes a single anonymous-tagged element via put and decodes
// it back into a real tlv.Element, so formatTLVElement is exercised against
// the actual decoder rather than a hand-rolled mock.
func buildElement(t *testing.T, put func(enc tlv.Encoder)) tlv.Element {
	t.Helper()
	enc := tlv.NewEncoder()
	put(enc)
	dec := tlv.NewDecoderWithBytes(enc.Bytes())
	if !dec.Next() {
		t.Fatalf("decode error: %v", dec.Error())
	}
	return dec.Element()
}

func TestFormatTLVElement(t *testing.T) {
	tests := []struct {
		name string
		put  func(enc tlv.Encoder)
		want string
	}{
		{name: "bool", put: func(enc tlv.Encoder) { enc.PutBool(tlv.NewAnonymousTag(), true) }, want: "true"},
		{name: "unsigned", put: func(enc tlv.Encoder) { enc.PutUnsigned2(tlv.NewAnonymousTag(), 42) }, want: "42"},
		{name: "signed", put: func(enc tlv.Encoder) { enc.PutSigned2(tlv.NewAnonymousTag(), -7) }, want: "-7"},
		{name: "float", put: func(enc tlv.Encoder) { enc.PutFloat32(tlv.NewAnonymousTag(), 1.5) }, want: "1.5"},
		{name: "utf8", put: func(enc tlv.Encoder) {
			if err := enc.PutUTF81(tlv.NewAnonymousTag(), "hello"); err != nil {
				t.Fatal(err)
			}
		}, want: "hello"},
		{name: "bytes", put: func(enc tlv.Encoder) {
			if err := enc.PutOctet1(tlv.NewAnonymousTag(), []byte{0xDE, 0xAD}); err != nil {
				t.Fatal(err)
			}
		}, want: "0xdead"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			elem := buildElement(t, tt.put)
			if got := formatTLVElement(elem); got != tt.want {
				t.Errorf("formatTLVElement(%s) = %q, want %q", tt.name, got, tt.want)
			}
		})
	}
}

// captureStdout redirects os.Stdout for the duration of f and returns
// whatever was written to it. outputf/printNamedValue/printFields hard-code
// fmt.Printf/os.Stdout with no injectable writer (the same pre-existing
// limitation scan.go already has), so this is the only way to assert on
// their output without changing that.
func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	f()

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestPrintNamedValueTable(t *testing.T) {
	out := captureStdout(t, func() {
		if err := printNamedValue(FormatTable, "vendor-id", uint16(0xFFF1)); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "vendor-id") || !strings.Contains(out, "65521") {
		t.Errorf("printNamedValue(table) output = %q, want it to contain name and value", out)
	}
}

func TestPrintNamedValueCSV(t *testing.T) {
	out := captureStdout(t, func() {
		if err := printNamedValue(FormatCSV, "vendor-id", uint16(0xFFF1)); err != nil {
			t.Fatal(err)
		}
	})
	if strings.TrimSpace(out) != "vendor-id,65521" {
		t.Errorf("printNamedValue(csv) output = %q, want %q", out, "vendor-id,65521\n")
	}
}

func TestPrintNamedValueJSON(t *testing.T) {
	out := captureStdout(t, func() {
		if err := printNamedValue(FormatJSON, "vendor-id", uint16(0xFFF1)); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, `"name": "vendor-id"`) || !strings.Contains(out, `"value": 65521`) {
		t.Errorf("printNamedValue(json) output = %q, want it to contain name/value fields", out)
	}
}

func TestPrintNamedValueList(t *testing.T) {
	out := captureStdout(t, func() {
		if err := printNamedValue(FormatTable, "server-list", []uint32{0x001D, 0x0028}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "server-list") {
		t.Errorf("printNamedValue(table, list) output = %q, want it to contain the attribute name", out)
	}
}
