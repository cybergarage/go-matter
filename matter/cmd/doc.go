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

package cmd

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

func init() {
	rootCmd.AddCommand(docCmd)
}

var docCmd = &cobra.Command{ // nolint:exhaustruct
	Use:   "doc",
	Short: "Generate markdown documentation to stdout",
	RunE: func(cmd *cobra.Command, args []string) error {
		emptyLinkHandler := func(name string) string {
			return ""
		}

		var appendMarkdown func(cmd *cobra.Command, buf *bytes.Buffer)
		appendMarkdown = func(cmd *cobra.Command, buf *bytes.Buffer) {
			doc.GenMarkdownCustom(cmd, buf, emptyLinkHandler)
			for _, c := range cmd.Commands() {
				appendMarkdown(c, buf)
			}
		}

		removeEmptySeeAlsoSections := func(md string) string {
			lines := strings.Split(md, "\n")
			var out []string
			for i := 0; i < len(lines); i++ {
				// Check for start of a meaningless SEE ALSO section (only an empty link follows)
				// ### SEE ALSO
				//
				// * [mdnsctl]()	 -
				if i < len(lines)-2 && strings.HasPrefix(lines[i], "### SEE ALSO") {
					// Skip these two lines as they do not provide any meaningful information
					i += 2 // skip the next two lines
					continue
				}
				out = append(out, lines[i])
			}
			return strings.Join(out, "\n")
		}

		var buf bytes.Buffer
		appendMarkdown(rootCmd, &buf)
		// ---- Post-process: Remove meaningless SEE ALSO sections ----
		docStr := buf.String()
		filteredDocStr := removeEmptySeeAlsoSections(docStr)
		fmt.Print(filteredDocStr)

		return nil
	},
}
