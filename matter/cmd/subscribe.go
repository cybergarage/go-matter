// Copyright (C) 2026 The go-matter Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cybergarage/go-matter/matter"
	"github.com/cybergarage/go-matter/matter/protocol/im"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	anySubscribeMinIntervalFlag = "min-interval"
	anySubscribeMaxIntervalFlag = "max-interval"
)

func init() {
	anySubscribeCmd.Flags().Duration(anySubscribeMinIntervalFlag, 0, "the least time between two reports")
	anySubscribeCmd.Flags().Duration(anySubscribeMaxIntervalFlag, im.DefaultSubscribeMaxInterval, "the most time the device may let pass without a report")
	anyCmd.AddCommand(anySubscribeCmd)
}

var anySubscribeCmd = &cobra.Command{ // nolint:exhaustruct
	Use:   "subscribe <cluster-id> <attribute-id|*> <node ID> <endpoint ID>",
	Short: "Subscribe to an attribute, or to every attribute of a cluster, and print the reports until interrupted.",
	Args:  cobra.ExactArgs(4),
	RunE:  runAnySubscribe,
}

func runAnySubscribe(cmd *cobra.Command, args []string) error {
	clusterIDArg, attributeIDArg, nodeIDArg, endpointIDArg := args[0], args[1], args[2], args[3]

	format, err := NewFormatFromString(viper.GetString(FormatParamStr))
	if err != nil {
		return err
	}
	clusterID, err := parseClusterID(clusterIDArg)
	if err != nil {
		return err
	}
	endpointID, err := parseEndpointID(endpointIDArg)
	if err != nil {
		return err
	}
	path := im.AttributeRequestPath{Endpoint: &endpointID, Cluster: &clusterID, Attribute: nil}
	if attributeIDArg != "*" {
		attributeID, err := parseAttributeID(attributeIDArg)
		if err != nil {
			return err
		}
		path.Attribute = &attributeID
	}
	minInterval, err := cmd.Flags().GetDuration(anySubscribeMinIntervalFlag)
	if err != nil {
		return err
	}
	maxInterval, err := cmd.Flags().GetDuration(anySubscribeMaxIntervalFlag)
	if err != nil {
		return err
	}

	node, _, err := connectNode(context.Background(), nodeIDArg)
	if err != nil {
		return err
	}
	defer node.Close()
	subscriber, ok := node.(matter.AttributeSubscriber)
	if !ok {
		return errors.New("any subscribe: the node does not support subscriptions")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	sub, err := subscriber.Subscribe(ctx, []im.AttributeRequestPath{path},
		func(r *im.Report) {
			for _, a := range r.Attributes {
				name := fmt.Sprintf("%s 0x%04X/0x%04X/0x%04X", time.Now().Format(time.TimeOnly), a.Path.Endpoint, a.Path.Cluster, a.Path.Attribute)
				var value any
				if a.Status != nil {
					value = fmt.Sprintf("status 0x%02X", a.Status.IMStatus)
				} else {
					value = formatAttributeValue(a.Value)
				}
				if err := printNamedValue(format, name, value); err != nil {
					fmt.Fprintln(os.Stderr, err)
				}
			}
		},
		im.WithMinInterval(minInterval),
		im.WithMaxInterval(maxInterval),
		im.WithSubscribeErrorHandler(func(err error) { fmt.Fprintln(os.Stderr, err) }))
	if err != nil {
		return err
	}
	defer sub.Close()

	select {
	case <-ctx.Done():
		return nil
	case <-sub.Done():
		return sub.Err()
	}
}

// formatAttributeValue renders a structured attribute value: a scalar as
// formatTLVElement does, an array or a list as [...] and a structure as
// {tag: value, ...}.
func formatAttributeValue(v *im.AttributeValue) string {
	if v == nil {
		return ""
	}
	t := v.Element.Type()
	if !t.IsContainer() {
		return formatTLVElement(v.Element)
	}
	parts := make([]string, 0, len(v.Children))
	for _, c := range v.Children {
		if t.IsStructure() {
			parts = append(parts, fmt.Sprintf("%v: %s", c.Element.Tag(), formatAttributeValue(c)))
		} else {
			parts = append(parts, formatAttributeValue(c))
		}
	}
	if t.IsStructure() {
		return "{" + strings.Join(parts, ", ") + "}"
	}
	return "[" + strings.Join(parts, ", ") + "]"
}
