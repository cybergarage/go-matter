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

	"github.com/cybergarage/go-matter/matter/cluster/accesscontrol"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	accesscontrolCmd.AddCommand(accesscontrolReadCmd)
	rootCmd.AddCommand(accesscontrolCmd)
}

var accesscontrolCmd = &cobra.Command{ // nolint:exhaustruct
	Use:   "accesscontrol",
	Short: "Access Control cluster (0x001F) commands.",
}

var accesscontrolReadCmd = &cobra.Command{ // nolint:exhaustruct
	Use:   readAttributeUse,
	Short: "Read an Access Control cluster attribute.",
	Args:  cobra.ExactArgs(3),
	RunE:  runAccesscontrolRead,
}

func runAccesscontrolRead(cmd *cobra.Command, args []string) error {
	attrName, nodeIDArg, endpointIDArg := args[0], args[1], args[2]

	switch attrName {
	case "subjects-per-access-control-entry", "targets-per-access-control-entry", "access-control-entries-per-fabric":
	default:
		return fmt.Errorf("accesscontrol: unknown attribute %q (want one of: subjects-per-access-control-entry, targets-per-access-control-entry, access-control-entries-per-fabric)", attrName)
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

	sess := node.Session()
	switch attrName {
	case "subjects-per-access-control-entry":
		v, err := accesscontrol.SubjectsPerAccessControlEntry(sess, endpointID)
		if err != nil {
			return err
		}
		return printNamedValue(format, attrName, v)
	case "targets-per-access-control-entry":
		v, err := accesscontrol.TargetsPerAccessControlEntry(sess, endpointID)
		if err != nil {
			return err
		}
		return printNamedValue(format, attrName, v)
	default: // "access-control-entries-per-fabric"
		v, err := accesscontrol.AccessControlEntriesPerFabric(sess, endpointID)
		if err != nil {
			return err
		}
		return printNamedValue(format, attrName, v)
	}
}
