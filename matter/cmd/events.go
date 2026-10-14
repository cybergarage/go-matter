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
	"syscall"
	"time"

	"github.com/cybergarage/go-matter/matter"
	"github.com/cybergarage/go-matter/matter/protocol/im"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const anyEventMinFlag = "event-min"

func init() {
	anyReadEventsCmd.Flags().Uint64(anyEventMinFlag, 0, "read the events numbered this and up only")
	anySubscribeEventsCmd.Flags().Uint64(anyEventMinFlag, 0, "report the kept events numbered this and up only")
	anySubscribeEventsCmd.Flags().Duration(anySubscribeMinIntervalFlag, 0, "the least time between two reports")
	anySubscribeEventsCmd.Flags().Duration(anySubscribeMaxIntervalFlag, im.DefaultSubscribeMaxInterval, "the most time the device may let pass without a report")
	anyCmd.AddCommand(anyReadEventsCmd)
	anyCmd.AddCommand(anySubscribeEventsCmd)
}

var anyReadEventsCmd = &cobra.Command{ // nolint:exhaustruct
	Use:   "read-events <cluster-id> <event-id|*> <node ID> <endpoint ID>",
	Short: "Read the events a node keeps of an event, or of every event of a cluster.",
	Args:  cobra.ExactArgs(4),
	RunE:  runAnyReadEvents,
}

var anySubscribeEventsCmd = &cobra.Command{ // nolint:exhaustruct
	Use:   "subscribe-events <cluster-id> <event-id|*> <node ID> <endpoint ID>",
	Short: "Subscribe to an event, or to every event of a cluster, and print them until interrupted.",
	Args:  cobra.ExactArgs(4),
	RunE:  runAnySubscribeEvents,
}

// parseEventRequestPath parses the cluster, event and endpoint arguments of
// an event command; "*" is every event of the cluster.
func parseEventRequestPath(clusterIDArg, eventIDArg, endpointIDArg string) (im.EventRequestPath, error) {
	clusterID, err := parseClusterID(clusterIDArg)
	if err != nil {
		return im.EventRequestPath{}, err
	}
	endpointID, err := parseEndpointID(endpointIDArg)
	if err != nil {
		return im.EventRequestPath{}, err
	}
	path := im.EventRequestPath{Endpoint: &endpointID, Cluster: &clusterID, Event: nil, IsUrgent: false}
	if eventIDArg != "*" {
		v, err := parseUint64(eventIDArg)
		if err != nil || v > 0xFFFFFFFF {
			return im.EventRequestPath{}, fmt.Errorf("invalid event ID %q", eventIDArg)
		}
		eventID := im.EventID(v)
		path.Event = &eventID
	}
	return path, nil
}

func printEvents(format Format, events []im.EventReport) {
	for _, e := range events {
		name := fmt.Sprintf("#%d 0x%04X/0x%04X/0x%04X", e.EventNumber, e.Path.Endpoint, e.Path.Cluster, e.Path.Event)
		var value string
		switch {
		case e.Status != nil:
			value = fmt.Sprintf("status 0x%02X", e.Status.IMStatus)
		default:
			when := fmt.Sprintf("%dms since boot", e.Timestamp)
			if at, ok := e.Time(); ok {
				when = at.Format(time.RFC3339Nano)
			}
			value = fmt.Sprintf("%s %s %s", when, e.Priority, formatAttributeValue(e.Data))
		}
		if err := printNamedValue(format, name, value); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}
}

func runAnyReadEvents(cmd *cobra.Command, args []string) error {
	format, err := NewFormatFromString(viper.GetString(FormatParamStr))
	if err != nil {
		return err
	}
	path, err := parseEventRequestPath(args[0], args[1], args[3])
	if err != nil {
		return err
	}
	var opts []im.ReadEventsOption
	if cmd.Flags().Changed(anyEventMinFlag) {
		n, err := cmd.Flags().GetUint64(anyEventMinFlag)
		if err != nil {
			return err
		}
		opts = append(opts, im.WithReadEventMin(n))
	}
	node, _, err := connectNode(context.Background(), args[2])
	if err != nil {
		return err
	}
	defer node.Close()
	reader, ok := node.(matter.EventReader)
	if !ok {
		return errors.New("any read-events: the node does not read events")
	}
	events, err := reader.ReadEvents([]im.EventRequestPath{path}, opts...)
	if err != nil {
		return err
	}
	printEvents(format, events)
	return nil
}

func runAnySubscribeEvents(cmd *cobra.Command, args []string) error {
	format, err := NewFormatFromString(viper.GetString(FormatParamStr))
	if err != nil {
		return err
	}
	path, err := parseEventRequestPath(args[0], args[1], args[3])
	if err != nil {
		return err
	}
	minInterval, err := cmd.Flags().GetDuration(anySubscribeMinIntervalFlag)
	if err != nil {
		return err
	}
	maxInterval, err := cmd.Flags().GetDuration(anySubscribeMaxIntervalFlag)
	if err != nil {
		return err
	}
	opts := []im.SubscribeOption{
		im.WithEvents(path),
		im.WithMinInterval(minInterval),
		im.WithMaxInterval(maxInterval),
		im.WithSubscribeErrorHandler(func(err error) { fmt.Fprintln(os.Stderr, err) }),
	}
	if cmd.Flags().Changed(anyEventMinFlag) {
		n, err := cmd.Flags().GetUint64(anyEventMinFlag)
		if err != nil {
			return err
		}
		opts = append(opts, im.WithEventMin(n))
	}
	node, _, err := connectNode(context.Background(), args[2])
	if err != nil {
		return err
	}
	defer node.Close()
	subscriber, ok := node.(matter.AttributeSubscriber)
	if !ok {
		return errors.New("any subscribe-events: the node does not support subscriptions")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	sub, err := subscriber.Subscribe(ctx, nil, func(r *im.Report) { printEvents(format, r.Events) }, opts...)
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
