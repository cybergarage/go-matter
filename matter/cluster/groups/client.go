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

// Package groups provides a client for the Matter Groups cluster
// (0x0004), which puts a node's endpoints in groups.
// Reference: Matter Application Cluster Spec 1.5, Section 1.3.
package groups

import (
	"fmt"

	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	"github.com/cybergarage/go-matter/matter/protocol/im"
	"github.com/cybergarage/go-matter/matter/protocol/session"
)

// ClusterID is the Groups cluster identifier.
const ClusterID im.ClusterID = 0x0004

// Command IDs of the Groups cluster.
const (
	AddGroupCommandID    im.CommandID = 0x00
	RemoveGroupCommandID im.CommandID = 0x03
)

// AddGroup puts an endpoint in a group of the accessing fabric, which the
// fabric must have mapped to a key set.
func AddGroup(sess session.SecureSession, endpointID im.EndpointID, groupID uint16, name string) error {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewContextTag(1))
	enc.PutUnsigned2(tlv.NewContextTag(0), groupID)
	if err := enc.PutUTF8(tlv.NewContextTag(1), name); err != nil {
		return err
	}
	if err := enc.EndContainer(); err != nil {
		return err
	}
	return invokeGroupStatus(sess, endpointID, AddGroupCommandID, "AddGroup", enc.Bytes())
}

// RemoveGroup takes an endpoint out of a group of the accessing fabric.
func RemoveGroup(sess session.SecureSession, endpointID im.EndpointID, groupID uint16) error {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewContextTag(1))
	enc.PutUnsigned2(tlv.NewContextTag(0), groupID)
	if err := enc.EndContainer(); err != nil {
		return err
	}
	return invokeGroupStatus(sess, endpointID, RemoveGroupCommandID, "RemoveGroup", enc.Bytes())
}

// invokeGroupStatus invokes a command answered with {Status, GroupID}.
func invokeGroupStatus(sess session.SecureSession, endpointID im.EndpointID, command im.CommandID, name string, fields []byte) error {
	resp, err := im.Invoke(sess, endpointID, ClusterID, command, fields)
	if err != nil {
		return fmt.Errorf("groups: %s: %w", name, err)
	}
	if !resp.IsSuccess() {
		return fmt.Errorf("groups: %s failed: IM status 0x%02X", name, resp.Status.IMStatus)
	}
	if v, ok := resp.Field(0); ok {
		if status, _ := v.Unsigned(); status != 0 {
			return fmt.Errorf("groups: %s failed: status 0x%02X", name, status)
		}
	}
	return nil
}
