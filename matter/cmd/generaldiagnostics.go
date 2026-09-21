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
	"context"
	"fmt"

	"github.com/cybergarage/go-matter/matter/cluster/generaldiagnostics"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	generaldiagnosticsCmd.AddCommand(generaldiagnosticsReadCmd)
	rootCmd.AddCommand(generaldiagnosticsCmd)
}

var generaldiagnosticsCmd = &cobra.Command{ // nolint:exhaustruct
	Use:   "generaldiagnostics",
	Short: "General Diagnostics cluster (0x0033) commands.",
}

var generaldiagnosticsReadCmd = &cobra.Command{ // nolint:exhaustruct
	Use:   readAttributeUse,
	Short: "Read a General Diagnostics cluster attribute.",
	Args:  cobra.ExactArgs(3),
	RunE:  runGeneraldiagnosticsRead,
}

func runGeneraldiagnosticsRead(cmd *cobra.Command, args []string) error {
	attrName, nodeIDArg, endpointIDArg := args[0], args[1], args[2]

	if attrName != "reboot-count" {
		return fmt.Errorf("generaldiagnostics: unknown attribute %q (want one of: reboot-count)", attrName)
	}

	format, err := NewFormatFromString(viper.GetString(FormatParamStr))
	if err != nil {
		return err
	}
	endpointID, err := parseEndpointID(endpointIDArg)
	if err != nil {
		return err
	}

	node, _, err := connectNode(context.Background(), nodeIDArg)
	if err != nil {
		return err
	}
	defer node.Close()

	// RebootCount is nullable (11.13.6): some devices report it as null
	// rather than a concrete value — see generaldiagnostics.RebootCount's
	// doc comment.
	v, ok, err := generaldiagnostics.RebootCount(node.Session(), endpointID)
	if err != nil {
		return err
	}
	if !ok {
		return printNamedValue(format, attrName, "null")
	}
	return printNamedValue(format, attrName, v)
}
