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
	"slices"

	"github.com/cybergarage/go-matter/matter/cluster/basicinformation"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	basicinformationCmd.AddCommand(basicinformationReadCmd)
	rootCmd.AddCommand(basicinformationCmd)
}

var basicinformationCmd = &cobra.Command{ // nolint:exhaustruct
	Use:   "basicinformation",
	Short: "Basic Information cluster (0x0028) commands.",
}

var basicinformationReadCmd = &cobra.Command{ // nolint:exhaustruct
	Use:   readAttributeUse,
	Short: "Read a Basic Information cluster attribute.",
	Args:  cobra.ExactArgs(3),
	RunE:  runBasicinformationRead,
}

var basicinformationAttributeNames = []string{
	"data-model-revision",
	"vendor-name",
	"vendor-id",
	"product-name",
	"product-id",
	"node-label",
	"location",
	"hardware-version",
	"hardware-version-string",
	"software-version",
	"software-version-string",
	"serial-number",
	"unique-id",
}

func runBasicinformationRead(cmd *cobra.Command, args []string) error {
	attrName, nodeIDArg, endpointIDArg := args[0], args[1], args[2]

	known := slices.Contains(basicinformationAttributeNames, attrName)
	if !known {
		return fmt.Errorf("basicinformation: unknown attribute %q (want one of: %v)", attrName, basicinformationAttributeNames)
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
	case "data-model-revision":
		v, err := basicinformation.DataModelRevision(sess, endpointID)
		if err != nil {
			return err
		}
		return printNamedValue(format, attrName, v)
	case "vendor-name":
		v, err := basicinformation.VendorName(sess, endpointID)
		if err != nil {
			return err
		}
		return printNamedValue(format, attrName, v)
	case "vendor-id":
		v, err := basicinformation.VendorID(sess, endpointID)
		if err != nil {
			return err
		}
		return printNamedValue(format, attrName, v)
	case "product-name":
		v, err := basicinformation.ProductName(sess, endpointID)
		if err != nil {
			return err
		}
		return printNamedValue(format, attrName, v)
	case "product-id":
		v, err := basicinformation.ProductID(sess, endpointID)
		if err != nil {
			return err
		}
		return printNamedValue(format, attrName, v)
	case "node-label":
		v, err := basicinformation.NodeLabel(sess, endpointID)
		if err != nil {
			return err
		}
		return printNamedValue(format, attrName, v)
	case "location":
		v, err := basicinformation.Location(sess, endpointID)
		if err != nil {
			return err
		}
		return printNamedValue(format, attrName, v)
	case "hardware-version":
		v, err := basicinformation.HardwareVersion(sess, endpointID)
		if err != nil {
			return err
		}
		return printNamedValue(format, attrName, v)
	case "hardware-version-string":
		v, err := basicinformation.HardwareVersionString(sess, endpointID)
		if err != nil {
			return err
		}
		return printNamedValue(format, attrName, v)
	case "software-version":
		v, err := basicinformation.SoftwareVersion(sess, endpointID)
		if err != nil {
			return err
		}
		return printNamedValue(format, attrName, v)
	case "software-version-string":
		v, err := basicinformation.SoftwareVersionString(sess, endpointID)
		if err != nil {
			return err
		}
		return printNamedValue(format, attrName, v)
	case "serial-number":
		v, err := basicinformation.SerialNumber(sess, endpointID)
		if err != nil {
			return err
		}
		return printNamedValue(format, attrName, v)
	default: // "unique-id"
		v, err := basicinformation.UniqueID(sess, endpointID)
		if err != nil {
			return err
		}
		return printNamedValue(format, attrName, v)
	}
}
