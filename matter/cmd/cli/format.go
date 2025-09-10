// Copyright (C) 2025 The go-matter Authors. All rights reserved.
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

package cli

import (
	"fmt"
	"strings"
)

// Format represents the output format.
type Format int

const (
	FormatTable Format = iota
	FormatJSON
	FormatCSV
)

var (
	FormatParamStr = "format"
	FormatTableStr = "table"
	FormatJSONStr  = "json"
	FormatCSVStr   = "csv"
)

func allSupportedFormats() []string {
	return []string{
		FormatTableStr,
		FormatJSONStr,
		FormatCSVStr,
	}
}

var formatMap = map[string]Format{
	FormatTableStr: FormatTable,
	FormatJSONStr:  FormatJSON,
	FormatCSVStr:   FormatCSV,
}

// NewFormatFromString returns the format from the string.
func NewFormatFromString(s string) (Format, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if format, ok := formatMap[s]; ok {
		return format, nil
	}
	return FormatTable, fmt.Errorf("invalid format: %s", s)
}

// String returns the string representation of the format.
func (f Format) String() string {
	for k, v := range formatMap {
		if v == f {
			return k
		}
	}
	return "unknown"
}
