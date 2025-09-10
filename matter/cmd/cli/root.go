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
	"errors"
	"fmt"
	"strings"

	"github.com/cybergarage/go-matter/matter"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var rootCmd = &cobra.Command{ // nolint:exhaustruct
	Use:               "matterctl",
	Version:           matter.Version,
	Short:             "",
	Long:              "",
	DisableAutoGenTag: true,
}

func GetRootCommand() *cobra.Command {
	return rootCmd
}

var sharedCommissioner matter.Commissioner

func SharedCommissioner() matter.Commissioner {
	return sharedCommissioner
}

func Execute(commissioner matter.Commissioner) error {
	sharedCommissioner = commissioner
	if err := sharedCommissioner.Start(); err != nil {
		return err
	}
	err := rootCmd.Execute()
	return errors.Join(err, sharedCommissioner.Stop())
}

func init() {
	rootCmd.PersistentFlags().String(FormatParamStr, FormatTableStr, fmt.Sprintf("output format: %s", strings.Join(allSupportedFormats(), "|")))
	viper.BindPFlag(FormatParamStr, rootCmd.PersistentFlags().Lookup(FormatParamStr))
	viper.SetEnvPrefix("matter_ctl")
	viper.BindEnv(FormatParamStr) // MATTER_CTL_FORMAT
	viper.SetDefault(FormatParamStr, FormatTableStr)
}
