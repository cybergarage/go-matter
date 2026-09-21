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

// Package accesscontrol provides a client for the Matter Access Control cluster (0x001F).
// Reference: Matter Core Spec 1.5, Section 9.10.
package accesscontrol

import (
	"fmt"

	"github.com/cybergarage/go-matter/matter/protocol/im"
	"github.com/cybergarage/go-matter/matter/protocol/session"
)

// ClusterID is the Access Control cluster identifier.
// 9.10. Access Control Cluster.
const ClusterID im.ClusterID = 0x001F

// Attribute IDs for the Access Control cluster.
// 9.10.6. Attributes.
const (
	// SubjectsPerAccessControlEntryAttributeID reports the maximum number
	// of subjects per access control entry.
	SubjectsPerAccessControlEntryAttributeID im.AttributeID = 0x0002
	// TargetsPerAccessControlEntryAttributeID reports the maximum number
	// of targets per access control entry.
	TargetsPerAccessControlEntryAttributeID im.AttributeID = 0x0003
	// AccessControlEntriesPerFabricAttributeID reports the maximum number
	// of access control entries per fabric.
	AccessControlEntriesPerFabricAttributeID im.AttributeID = 0x0004
)

// SubjectsPerAccessControlEntry reads the SubjectsPerAccessControlEntry attribute of the given endpoint.
func SubjectsPerAccessControlEntry(sess session.SecureSession, endpointID im.EndpointID) (uint16, error) {
	return readUint16Attribute(sess, endpointID, SubjectsPerAccessControlEntryAttributeID, "SubjectsPerAccessControlEntry")
}

// TargetsPerAccessControlEntry reads the TargetsPerAccessControlEntry attribute of the given endpoint.
func TargetsPerAccessControlEntry(sess session.SecureSession, endpointID im.EndpointID) (uint16, error) {
	return readUint16Attribute(sess, endpointID, TargetsPerAccessControlEntryAttributeID, "TargetsPerAccessControlEntry")
}

// AccessControlEntriesPerFabric reads the AccessControlEntriesPerFabric attribute of the given endpoint.
func AccessControlEntriesPerFabric(sess session.SecureSession, endpointID im.EndpointID) (uint16, error) {
	return readUint16Attribute(sess, endpointID, AccessControlEntriesPerFabricAttributeID, "AccessControlEntriesPerFabric")
}

// readUint16Attribute reads a single UINT16 attribute of this cluster.
func readUint16Attribute(sess session.SecureSession, endpointID im.EndpointID, attributeID im.AttributeID, name string) (uint16, error) {
	resp, err := im.ReadAttribute(sess, endpointID, ClusterID, attributeID)
	if err != nil {
		return 0, fmt.Errorf("accesscontrol: %s: %w", name, err)
	}
	if resp.Status != nil {
		return 0, fmt.Errorf("accesscontrol: %s failed: IM status 0x%02X, cluster status 0x%02X",
			name, resp.Status.IMStatus, resp.Status.ClusterStatus)
	}
	if resp.Value == nil {
		return 0, fmt.Errorf("accesscontrol: %s: ReadResponse missing attribute value", name)
	}
	v, ok := resp.Value.Unsigned2()
	if !ok {
		return 0, fmt.Errorf("accesscontrol: %s: attribute value is not a UINT16", name)
	}
	return v, nil
}
