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
	"errors"
	"fmt"
	"strings"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	ProgramName     = "matterctl"
	FormatParamStr  = "format"
	VerboseParamStr = "verbose"
	DebugParamStr   = "debug"
)

var rootCmd = &cobra.Command{ // nolint:exhaustruct
	Use:               ProgramName,
	Version:           matter.Version,
	Short:             "",
	Long:              "",
	DisableAutoGenTag: true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		log.SetSharedLogger(nil)
		verbose := viper.GetBool(VerboseParamStr)
		debug := viper.GetBool(DebugParamStr)
		if debug {
			verbose = true
		}
		if verbose {
			log.Infof("%s version %s", ProgramName, matter.Version)
			log.Infof("verbose:%t, debug:%t", verbose, debug)
			if debug {
				log.SetSharedLogger(log.NewStdoutLogger(log.LevelDebug))
			} else {
				log.SetSharedLogger(log.NewStdoutLogger(log.LevelInfo))
			}
		}
		return nil
	},
}

// RootCommand returns the root command.
func RootCommand() *cobra.Command {
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
	viper.SetEnvPrefix("matter_ctl")

	viper.SetDefault(FormatParamStr, FormatTableStr)
	rootCmd.PersistentFlags().String(FormatParamStr, FormatTableStr, fmt.Sprintf("output format: %s", strings.Join(allSupportedFormats(), "|")))
	viper.BindPFlag(FormatParamStr, rootCmd.PersistentFlags().Lookup(FormatParamStr))
	viper.BindEnv(FormatParamStr) // MATTER_CTL_FORMAT

	viper.SetDefault(VerboseParamStr, false)
	rootCmd.PersistentFlags().Bool((VerboseParamStr), false, "enable verbose output")
	viper.BindPFlag(VerboseParamStr, rootCmd.PersistentFlags().Lookup(VerboseParamStr))
	viper.BindEnv(VerboseParamStr) // MATTER_CTL_VERBOSE

	viper.SetDefault(DebugParamStr, false)
	rootCmd.PersistentFlags().Bool((DebugParamStr), false, "enable debug output")
	viper.BindPFlag(DebugParamStr, rootCmd.PersistentFlags().Lookup(DebugParamStr))
	viper.BindEnv(DebugParamStr) // MATTER_CTL_DEBUG
}
