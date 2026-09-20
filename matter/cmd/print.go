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
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/cybergarage/go-matter/matter/encoding/tlv"
)

// printNamedValue prints a single attribute/command result under name,
// honoring the --format flag. value may be a scalar (bool, string, uint16,
// ...) or a slice thereof — both render as a single NAME/VALUE row in
// table/csv (via %v), or natively in json.
func printNamedValue(format Format, name string, value any) error {
	switch format {
	case FormatJSON:
		b, err := json.MarshalIndent(map[string]any{"name": name, "value": value}, "", "  ")
		if err != nil {
			return err
		}
		outputf("%s\n", string(b))
		return nil
	case FormatCSV:
		outputf("%s,%v\n", name, value)
		return nil
	default: // FormatTable
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
		fmt.Fprintf(w, "NAME\tVALUE\n")
		fmt.Fprintf(w, "%s\t%v\n", name, value)
		return w.Flush()
	}
}

// printFields prints an Invoke response's named fields (im.InvokeResponse's
// Payload, keyed by context tag number), one row per tag, honoring
// --format. Kept separate from printNamedValue since its shape genuinely
// differs (multiple named fields, not one name/value pair).
func printFields(format Format, fields map[uint8]tlv.Element) error {
	switch format {
	case FormatJSON:
		out := make(map[string]string, len(fields))
		for tag, elem := range fields {
			out[fmt.Sprintf("%d", tag)] = formatTLVElement(elem)
		}
		b, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return err
		}
		outputf("%s\n", string(b))
		return nil
	case FormatCSV:
		for tag, elem := range fields {
			outputf("%d,%s\n", tag, formatTLVElement(elem))
		}
		return nil
	default: // FormatTable
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
		fmt.Fprintf(w, "TAG\tVALUE\n")
		for tag, elem := range fields {
			fmt.Fprintf(w, "%d\t%s\n", tag, formatTLVElement(elem))
		}
		return w.Flush()
	}
}

// formatTLVElement renders a tlv.Element's decoded value as a printable
// string, used by `any read`/`any invoke` where the Go type is not known
// ahead of time. Tries typed accessors in order of "most specific / least
// surprising first": Bool, then Unsigned, then Signed, then Float, then
// UTF8, then Bytes (rendered as 0x-prefixed hex), falling back to
// Element.String() for containers/null/anything else.
func formatTLVElement(elem tlv.Element) string {
	if v, ok := elem.Bool(); ok {
		return fmt.Sprintf("%t", v)
	}
	if v, ok := elem.Unsigned(); ok {
		return fmt.Sprintf("%d", v)
	}
	if v, ok := elem.Signed(); ok {
		return fmt.Sprintf("%d", v)
	}
	if v, ok := elem.Float(); ok {
		return fmt.Sprintf("%g", v)
	}
	if v, ok := elem.UTF8(); ok {
		return v
	}
	if v, ok := elem.Bytes(); ok {
		return fmt.Sprintf("0x%x", v)
	}
	return elem.String()
}
