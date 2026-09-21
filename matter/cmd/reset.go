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
	"fmt"
	"os"
	"path/filepath"

	"github.com/cybergarage/go-logger/log"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(resetCmd)
}

var resetCmd = &cobra.Command{ // nolint:exhaustruct
	Use:   "reset",
	Short: "Remove the local persistence directory.",
	Long:  fmt.Sprintf("Remove ~/.%s, deleting the persisted fabric identity and commissioned-device records. For testing only.", ProgramName),
	RunE: func(cmd *cobra.Command, args []string) error {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("resolve home directory: %w", err)
		}
		dir := filepath.Join(home, "."+ProgramName)

		if _, err := os.Stat(dir); os.IsNotExist(err) {
			log.Infof("%s does not exist", dir)
			return nil
		}

		if err := os.RemoveAll(dir); err != nil {
			return fmt.Errorf("remove %s: %w", dir, err)
		}

		log.Infof("Removed %s", dir)

		return nil
	},
}
