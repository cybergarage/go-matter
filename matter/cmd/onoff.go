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

	"github.com/cybergarage/go-matter/matter/cluster/onoff"
	"github.com/cybergarage/go-matter/matter/protocol/im"
	"github.com/cybergarage/go-matter/matter/protocol/session"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	onoffCmd.AddCommand(onoffOnCmd)
	onoffCmd.AddCommand(onoffOffCmd)
	onoffCmd.AddCommand(onoffToggleCmd)
	onoffCmd.AddCommand(onoffReadCmd)
	rootCmd.AddCommand(onoffCmd)
}

var onoffCmd = &cobra.Command{ // nolint:exhaustruct
	Use:   "onoff",
	Short: "On/Off cluster (0x0006) commands.",
}

var onoffOnCmd = &cobra.Command{ // nolint:exhaustruct
	Use:   "on <node ID> <endpoint ID>",
	Short: "Invoke the On command.",
	Args:  cobra.ExactArgs(2),
	RunE:  runOnOffInvoke(onoff.On),
}

var onoffOffCmd = &cobra.Command{ // nolint:exhaustruct
	Use:   "off <node ID> <endpoint ID>",
	Short: "Invoke the Off command.",
	Args:  cobra.ExactArgs(2),
	RunE:  runOnOffInvoke(onoff.Off),
}

var onoffToggleCmd = &cobra.Command{ // nolint:exhaustruct
	Use:   "toggle <node ID> <endpoint ID>",
	Short: "Invoke the Toggle command.",
	Args:  cobra.ExactArgs(2),
	RunE:  runOnOffInvoke(onoff.Toggle),
}

var onoffReadCmd = &cobra.Command{ // nolint:exhaustruct
	Use:   readAttributeUse,
	Short: "Read an On/Off cluster attribute.",
	Args:  cobra.ExactArgs(3),
	RunE:  runOnOffRead,
}

// runOnOffInvoke builds a RunE for a field-less On/Off command (On/Off/Toggle
// all share the same 2-positional-arg, zero-return shape).
func runOnOffInvoke(fn func(sess session.SecureSession, endpointID im.EndpointID) error) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		nodeIDArg, endpointIDArg := args[0], args[1]

		endpointID, err := parseEndpointID(endpointIDArg)
		if err != nil {
			return err
		}

		node, _, err := connectNode(context.Background(), nodeIDArg)
		if err != nil {
			return err
		}
		defer node.Close()

		return fn(node.Session(), endpointID)
	}
}

func runOnOffRead(cmd *cobra.Command, args []string) error {
	attrName, nodeIDArg, endpointIDArg := args[0], args[1], args[2]

	if attrName != "on-off" {
		return fmt.Errorf("onoff: unknown attribute %q (want: on-off)", attrName)
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

	v, err := onoff.OnOff(node.Session(), endpointID)
	if err != nil {
		return err
	}
	return printNamedValue(format, attrName, v)
}
