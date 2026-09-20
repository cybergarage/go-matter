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
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const anyWriteTypeFlag = "type"
const anyInvokeFieldsFlag = "fields"

func init() {
	anyWriteCmd.Flags().String(anyWriteTypeFlag, "uint", "value encoding: bool|uint|int|string|hex")
	anyInvokeCmd.Flags().String(anyInvokeFieldsFlag, "", "raw hex-encoded TLV command-fields blob; omitted means no command fields")

	anyCmd.AddCommand(anyReadCmd)
	anyCmd.AddCommand(anyWriteCmd)
	anyCmd.AddCommand(anyInvokeCmd)
	rootCmd.AddCommand(anyCmd)
}

var anyCmd = &cobra.Command{ // nolint:exhaustruct
	Use:   "any",
	Short: "Read/write/invoke any cluster by numeric ID (for clusters without a named command).",
}

var anyReadCmd = &cobra.Command{ // nolint:exhaustruct
	Use:   "read <cluster-id> <attribute-id> <node ID> <endpoint ID>",
	Short: "Read an attribute by numeric cluster/attribute ID.",
	Args:  cobra.ExactArgs(4),
	RunE:  runAnyRead,
}

var anyWriteCmd = &cobra.Command{ // nolint:exhaustruct
	Use:   "write <cluster-id> <attribute-id> <value> <node ID> <endpoint ID>",
	Short: "Write an attribute by numeric cluster/attribute ID.",
	Args:  cobra.ExactArgs(5),
	RunE:  runAnyWrite,
}

var anyInvokeCmd = &cobra.Command{ // nolint:exhaustruct
	Use:   "invoke <cluster-id> <command-id> <node ID> <endpoint ID>",
	Short: "Invoke a command by numeric cluster/command ID.",
	Args:  cobra.ExactArgs(4),
	RunE:  runAnyInvoke,
}

func runAnyRead(cmd *cobra.Command, args []string) error {
	clusterIDArg, attributeIDArg, nodeIDArg, endpointIDArg := args[0], args[1], args[2], args[3]

	format, err := NewFormatFromString(viper.GetString(FormatParamStr))
	if err != nil {
		return err
	}
	clusterID, err := parseClusterID(clusterIDArg)
	if err != nil {
		return err
	}
	attributeID, err := parseAttributeID(attributeIDArg)
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

	resp, err := node.ReadAttribute(endpointID, clusterID, attributeID)
	if err != nil {
		return err
	}
	if resp.Status != nil {
		return fmt.Errorf("any read: IM status 0x%02X, cluster status 0x%02X", resp.Status.IMStatus, resp.Status.ClusterStatus)
	}
	if resp.Value == nil {
		return fmt.Errorf("any read: response missing attribute value")
	}
	return printNamedValue(format, attributeIDArg, formatTLVElement(resp.Value))
}

func runAnyWrite(cmd *cobra.Command, args []string) error {
	clusterIDArg, attributeIDArg, valueArg, nodeIDArg, endpointIDArg := args[0], args[1], args[2], args[3], args[4]

	valueType, err := cmd.Flags().GetString(anyWriteTypeFlag)
	if err != nil {
		return err
	}
	clusterID, err := parseClusterID(clusterIDArg)
	if err != nil {
		return err
	}
	attributeID, err := parseAttributeID(attributeIDArg)
	if err != nil {
		return err
	}
	endpointID, err := parseEndpointID(endpointIDArg)
	if err != nil {
		return err
	}
	encodeData, err := anyWriteEncoder(valueType, valueArg)
	if err != nil {
		return err
	}

	node, _, err := connectNode(context.Background(), nodeIDArg)
	if err != nil {
		return err
	}
	defer node.Close()

	resp, err := node.WriteAttribute(endpointID, clusterID, attributeID, encodeData)
	if err != nil {
		return err
	}
	if !resp.IsSuccess() {
		return fmt.Errorf("any write: IM status 0x%02X, cluster status 0x%02X", resp.Status.IMStatus, resp.Status.ClusterStatus)
	}
	return nil
}

// anyWriteEncoder builds the WriteAttribute encodeData callback for valueArg,
// encoded per valueType at the Data field's tag (tlv.NewContextTag(2)) — the
// confirmed WriteAttribute encodeData convention (matter/protocol/im/write_impl.go).
func anyWriteEncoder(valueType, valueArg string) (func(enc tlv.Encoder) error, error) {
	switch valueType {
	case "bool":
		v, err := strconv.ParseBool(valueArg)
		if err != nil {
			return nil, fmt.Errorf("invalid bool value %q: %w", valueArg, err)
		}
		return func(enc tlv.Encoder) error {
			enc.PutBool(tlv.NewContextTag(2), v)
			return nil
		}, nil
	case "uint":
		v, err := parseUint64(valueArg)
		if err != nil {
			return nil, fmt.Errorf("invalid uint value %q: %w", valueArg, err)
		}
		return func(enc tlv.Encoder) error {
			return enc.PutUnsigned(tlv.NewContextTag(2), v)
		}, nil
	case "int":
		v, err := strconv.ParseInt(valueArg, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid int value %q: %w", valueArg, err)
		}
		return func(enc tlv.Encoder) error {
			return enc.PutSigned(tlv.NewContextTag(2), v)
		}, nil
	case "string":
		return func(enc tlv.Encoder) error {
			return enc.PutUTF8(tlv.NewContextTag(2), valueArg)
		}, nil
	case "hex":
		b, err := hex.DecodeString(strings.TrimPrefix(valueArg, "0x"))
		if err != nil {
			return nil, fmt.Errorf("invalid hex value %q: %w", valueArg, err)
		}
		return func(enc tlv.Encoder) error {
			return enc.PutOctet(tlv.NewContextTag(2), b)
		}, nil
	default:
		return nil, fmt.Errorf("unsupported --%s %q (want one of: bool, uint, int, string, hex)", anyWriteTypeFlag, valueType)
	}
}

func runAnyInvoke(cmd *cobra.Command, args []string) error {
	clusterIDArg, commandIDArg, nodeIDArg, endpointIDArg := args[0], args[1], args[2], args[3]

	format, err := NewFormatFromString(viper.GetString(FormatParamStr))
	if err != nil {
		return err
	}
	clusterID, err := parseClusterID(clusterIDArg)
	if err != nil {
		return err
	}
	commandID, err := parseCommandID(commandIDArg)
	if err != nil {
		return err
	}
	endpointID, err := parseEndpointID(endpointIDArg)
	if err != nil {
		return err
	}
	fieldsArg, err := cmd.Flags().GetString(anyInvokeFieldsFlag)
	if err != nil {
		return err
	}
	var fields []byte
	if fieldsArg != "" {
		fields, err = hex.DecodeString(strings.TrimPrefix(fieldsArg, "0x"))
		if err != nil {
			return fmt.Errorf("invalid --%s %q: %w", anyInvokeFieldsFlag, fieldsArg, err)
		}
	}

	node, _, err := connectNode(context.Background(), nodeIDArg)
	if err != nil {
		return err
	}
	defer node.Close()

	resp, err := node.Invoke(endpointID, clusterID, commandID, fields)
	if err != nil {
		return err
	}
	if !resp.IsSuccess() {
		return fmt.Errorf("any invoke: IM status 0x%02X, cluster status 0x%02X", resp.Status.IMStatus, resp.Status.ClusterStatus)
	}
	return printFields(format, resp.Payload)
}
