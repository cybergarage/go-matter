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

	"github.com/cybergarage/go-matter/matter/cluster/descriptor"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	descriptorCmd.AddCommand(descriptorReadCmd)
	rootCmd.AddCommand(descriptorCmd)
}

var descriptorCmd = &cobra.Command{ // nolint:exhaustruct
	Use:   "descriptor",
	Short: "Descriptor cluster (0x001D) commands.",
}

var descriptorReadCmd = &cobra.Command{ // nolint:exhaustruct
	Use:   readAttributeUse,
	Short: "Read a Descriptor cluster attribute.",
	Args:  cobra.ExactArgs(3),
	RunE:  runDescriptorRead,
}

func runDescriptorRead(cmd *cobra.Command, args []string) error {
	attrName, nodeIDArg, endpointIDArg := args[0], args[1], args[2]

	switch attrName {
	case "device-type-list", "server-list", "client-list", "parts-list":
	default:
		return fmt.Errorf("descriptor: unknown attribute %q (want one of: device-type-list, server-list, client-list, parts-list)", attrName)
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

	switch attrName {
	case "device-type-list":
		v, err := descriptor.DeviceTypeList(node.Session(), endpointID)
		if err != nil {
			return err
		}
		return printNamedValue(format, attrName, v)
	case "server-list":
		v, err := descriptor.ServerList(node.Session(), endpointID)
		if err != nil {
			return err
		}
		return printNamedValue(format, attrName, v)
	case "client-list":
		v, err := descriptor.ClientList(node.Session(), endpointID)
		if err != nil {
			return err
		}
		return printNamedValue(format, attrName, v)
	default: // "parts-list"
		v, err := descriptor.PartsList(node.Session(), endpointID)
		if err != nil {
			return err
		}
		return printNamedValue(format, attrName, v)
	}
}
