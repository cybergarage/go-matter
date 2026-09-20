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
	"strconv"
	"strings"

	"github.com/cybergarage/go-matter/matter"
	"github.com/cybergarage/go-matter/matter/protocol/im"
)

// readAttributeUse is the shared Cobra Use string for every cluster's
// "read a named attribute" subcommand (descriptor, basicinformation, onoff).
const readAttributeUse = "read <attribute-name> <node ID> <endpoint ID>"

// parseUint64 parses s as a decimal number, or as hexadecimal when prefixed
// with "0x"/"0X" — matching chip-tool's own node-ID/cluster-ID/attribute-ID/
// command-ID argument convention: "a decimal number or a 0x-prefixed hex
// number". strconv.ParseUint(s, 0, 64) is deliberately NOT used here since
// its base-0 auto-detection treats a leading "0" as octal (e.g. "0123" ->
// 83 decimal), which chip-tool does not do and would silently corrupt an ID
// pasted with leading zeros.
func parseUint64(s string) (uint64, error) {
	if s == "" {
		return 0, fmt.Errorf("empty numeric argument")
	}
	if hex, ok := strings.CutPrefix(s, "0x"); ok {
		return strconv.ParseUint(hex, 16, 64)
	}
	if hex, ok := strings.CutPrefix(s, "0X"); ok {
		return strconv.ParseUint(hex, 16, 64)
	}
	return strconv.ParseUint(s, 10, 64)
}

// parseEndpointID parses s (decimal or 0x-hex) as an EndpointID.
func parseEndpointID(s string) (im.EndpointID, error) {
	v, err := parseUint64(s)
	if err != nil {
		return 0, fmt.Errorf("invalid endpoint ID %q: %w", s, err)
	}
	if v > 0xFFFF {
		return 0, fmt.Errorf("endpoint ID %q out of range (max 0xFFFF)", s)
	}
	return im.EndpointID(v), nil
}

// parseClusterID parses s (decimal or 0x-hex) as a ClusterID.
func parseClusterID(s string) (im.ClusterID, error) {
	v, err := parseUint64(s)
	if err != nil {
		return 0, fmt.Errorf("invalid cluster ID %q: %w", s, err)
	}
	if v > 0xFFFFFFFF {
		return 0, fmt.Errorf("cluster ID %q out of range (max 0xFFFFFFFF)", s)
	}
	return im.ClusterID(v), nil
}

// parseAttributeID parses s (decimal or 0x-hex) as an AttributeID.
func parseAttributeID(s string) (im.AttributeID, error) {
	v, err := parseUint64(s)
	if err != nil {
		return 0, fmt.Errorf("invalid attribute ID %q: %w", s, err)
	}
	if v > 0xFFFFFFFF {
		return 0, fmt.Errorf("attribute ID %q out of range (max 0xFFFFFFFF)", s)
	}
	return im.AttributeID(v), nil
}

// parseCommandID parses s (decimal or 0x-hex) as a CommandID.
func parseCommandID(s string) (im.CommandID, error) {
	v, err := parseUint64(s)
	if err != nil {
		return 0, fmt.Errorf("invalid command ID %q: %w", s, err)
	}
	if v > 0xFFFFFFFF {
		return 0, fmt.Errorf("command ID %q out of range (max 0xFFFFFFFF)", s)
	}
	return im.CommandID(v), nil
}

// connectNode parses nodeIDArg and connects to it via the shared
// Commissioner. Callers must `defer node.Close()` on success. ctx does not
// need its own timeout — Commissioner.Connect already applies
// matter.DefaultConnectTimeout when ctx has no deadline of its own.
//
// KNOWN LIMITATION: the node ID a caller passes to `pairing code`/`pairing
// code-wifi` is NOT honored by Commission() today — a random operational
// node ID is assigned instead (see matter/commissioning_impl.go's
// commissionOperationalCredentials). Callers of connectNode must supply
// whatever node ID the device actually ended up with, not the one they
// requested at pairing time.
func connectNode(ctx context.Context, nodeIDArg string) (matter.Node, uint64, error) {
	nodeID, err := parseUint64(nodeIDArg)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid node ID %q: %w", nodeIDArg, err)
	}
	node, err := SharedCommissioner().Connect(ctx, nodeID)
	if err != nil {
		return nil, 0, err
	}
	return node, nodeID, nil
}
