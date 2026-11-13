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

	"github.com/cybergarage/go-matter/matter/datamodel"
	"github.com/cybergarage/go-matter/matter/datamodel/command"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	"github.com/cybergarage/go-matter/matter/protocol/im"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const anyWriteTypeFlag = "type"
const anyInvokeFieldsFlag = "fields"
const anyInvokeFieldFlag = "field"

func init() {
	anyWriteCmd.Flags().String(anyWriteTypeFlag, "uint", "value encoding: bool|uint|int|string|hex")
	anyInvokeCmd.Flags().String(anyInvokeFieldsFlag, "", "raw hex-encoded TLV command-fields blob; omitted means no command fields")
	anyInvokeCmd.Flags().StringArray(anyInvokeFieldFlag, nil, "command field as name=value, checked against the cluster definition (repeatable); e.g. --field Level=128")

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
	Long: `Invoke a command by numeric cluster/command ID.

The command fields are given in one of two ways:

  --field name=value   One field of the command, repeatable. The fields are
                       checked against the definition of the cluster in the
                       datamodel catalog and encoded from it. A value is a
                       number (decimal or 0x-hex), true or false, null, the
                       name of an enumeration value, names of bitmap bits
                       joined with "|", text, or hex for an octet string.
  --fields <hex>       The TLV-encoded command fields, sent as they are.

Only the clusters of the catalog can take --field; see
doc/matter-definition-db.md for the list.`,
	Example: `  # Level Control (0x0008) MoveToLevel (0x00): half brightness in one second
  matterctl any invoke 0x0008 0x00 <node ID> 1 \
    --field Level=127 --field TransitionTime=10 \
    --field OptionsMask=0 --field OptionsOverride=0`,
	Args: cobra.ExactArgs(4),
	RunE: runAnyInvoke,
}

// invokeFields returns the command fields of an invoke: the raw blob of
// --fields, or the fields of --field encoded from the datamodel catalog.
func invokeFields(clusterID im.ClusterID, commandID im.CommandID, rawHex string, fieldArgs []string) ([]byte, error) {
	if len(fieldArgs) == 0 {
		if rawHex == "" {
			return nil, nil
		}
		fields, err := hex.DecodeString(strings.TrimPrefix(rawHex, "0x"))
		if err != nil {
			return nil, fmt.Errorf("invalid --%s %q: %w", anyInvokeFieldsFlag, rawHex, err)
		}
		return fields, nil
	}
	if rawHex != "" {
		return nil, fmt.Errorf("--%s and --%s cannot be used together", anyInvokeFieldFlag, anyInvokeFieldsFlag)
	}
	catalog, err := datamodel.Load()
	if err != nil {
		return nil, err
	}
	schema, err := command.New(catalog, clusterID, commandID)
	if err != nil {
		return nil, err
	}
	// A command which requires a timed interaction is refused by the node
	// when it is sent as a plain invoke. 8.7.2. Timed Interaction.
	if schema.Timed {
		return nil, fmt.Errorf("%s %s requires a timed invoke, which matterctl does not send yet", schema.ClusterName, schema.CommandName)
	}
	values := map[string]any{}
	for _, arg := range fieldArgs {
		name, value, ok := strings.Cut(arg, "=")
		name = strings.TrimSpace(name)
		if !ok || name == "" {
			return nil, fmt.Errorf("invalid --%s %q: expected name=value", anyInvokeFieldFlag, arg)
		}
		f, known := schema.Field(name)
		if !known {
			return nil, fmt.Errorf("%w: %s %s has no field %q", command.ErrUnknownField, schema.ClusterName, schema.CommandName, name)
		}
		if _, dup := values[f.Name]; dup {
			return nil, fmt.Errorf("--%s %s given more than once", anyInvokeFieldFlag, f.Name)
		}
		values[f.Name] = value
	}
	return schema.Encode(values)
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
	fieldArgs, err := cmd.Flags().GetStringArray(anyInvokeFieldFlag)
	if err != nil {
		return err
	}
	fields, err := invokeFields(clusterID, commandID, fieldsArg, fieldArgs)
	if err != nil {
		return err
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
