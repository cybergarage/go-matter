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

// Package onoff provides a client for the Matter On/Off cluster (0x0006).
// Reference: Matter Core Spec 1.5, Section 1.5.
package onoff

import (
	"fmt"

	"github.com/cybergarage/go-matter/matter/protocol/im"
	"github.com/cybergarage/go-matter/matter/protocol/session"
)

// ClusterID is the On/Off cluster identifier.
// 1.5. On/Off Cluster.
const ClusterID im.ClusterID = 0x0006

// Attribute IDs for the On/Off cluster.
// 1.5.6. Attributes.
const (
	// OnOffAttributeID reports whether the device is in its "on" state.
	OnOffAttributeID im.AttributeID = 0x0000
)

// Command IDs for the On/Off cluster.
// 1.5.7. Commands.
const (
	OffCommandID    im.CommandID = 0x00
	OnCommandID     im.CommandID = 0x01
	ToggleCommandID im.CommandID = 0x02
)

// OnOff reads the OnOff attribute of the given endpoint.
func OnOff(sess session.SecureSession, endpointID im.EndpointID) (bool, error) {
	resp, err := im.ReadAttribute(sess, endpointID, ClusterID, OnOffAttributeID)
	if err != nil {
		return false, fmt.Errorf("onoff: OnOff: %w", err)
	}
	if resp.Status != nil {
		return false, fmt.Errorf("onoff: OnOff failed: IM status 0x%02X, cluster status 0x%02X",
			resp.Status.IMStatus, resp.Status.ClusterStatus)
	}
	if resp.Value == nil {
		return false, fmt.Errorf("onoff: OnOff: ReadResponse missing attribute value")
	}
	v, ok := resp.Value.Bool()
	if !ok {
		return false, fmt.Errorf("onoff: OnOff: attribute value is not a BOOL")
	}
	return v, nil
}

// On invokes the On command on the given endpoint.
// 1.5.7.3. On Command.
func On(sess session.SecureSession, endpointID im.EndpointID) error {
	return invoke(sess, endpointID, OnCommandID, "On")
}

// Off invokes the Off command on the given endpoint.
// 1.5.7.1. Off Command.
func Off(sess session.SecureSession, endpointID im.EndpointID) error {
	return invoke(sess, endpointID, OffCommandID, "Off")
}

// Toggle invokes the Toggle command on the given endpoint.
// 1.5.7.4. Toggle Command.
func Toggle(sess session.SecureSession, endpointID im.EndpointID) error {
	return invoke(sess, endpointID, ToggleCommandID, "Toggle")
}

// invoke sends the given (field-less) On/Off cluster command.
func invoke(sess session.SecureSession, endpointID im.EndpointID, commandID im.CommandID, name string) error {
	resp, err := im.Invoke(sess, endpointID, ClusterID, commandID, nil)
	if err != nil {
		return fmt.Errorf("onoff: %s: %w", name, err)
	}
	if !resp.IsSuccess() {
		return fmt.Errorf("onoff: %s failed: IM status 0x%02X, cluster status 0x%02X",
			name, resp.Status.IMStatus, resp.Status.ClusterStatus)
	}
	return nil
}
