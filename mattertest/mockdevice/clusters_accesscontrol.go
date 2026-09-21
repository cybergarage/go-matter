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

package mockdevice

import (
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	"github.com/cybergarage/go-matter/matter/protocol/im"
)

// Access Control cluster (0x001F) attribute IDs, per Matter Core Spec
// 9.10.6. The full ACL/Extension list attributes (nested struct-lists) are
// deliberately not modeled here — only the three fabric-scoped scalar
// limit attributes, which are enough to exercise a real IM read against a
// mandatory cluster without the complexity of encoding an
// AccessControlEntryStruct.
const (
	accessControlClusterID              im.ClusterID   = 0x001F
	subjectsPerAccessControlEntryAttrID im.AttributeID = 0x0002
	targetsPerAccessControlEntryAttrID  im.AttributeID = 0x0003
	accessControlEntriesPerFabricAttrID im.AttributeID = 0x0004

	mockSubjectsPerACLEntry uint16 = 4
	mockTargetsPerACLEntry  uint16 = 3
	mockACLEntriesPerFabric uint16 = 4
)

// registerAccessControlHandlers wires read-only access to
// SubjectsPerAccessControlEntry, TargetsPerAccessControlEntry and
// AccessControlEntriesPerFabric into srv.
func registerAccessControlHandlers(srv *imServer, d *Device) {
	srv.handleRead(defaultEndpointID, accessControlClusterID, subjectsPerAccessControlEntryAttrID, func() (func(enc tlv.Encoder) error, error) {
		return uint16Attribute(mockSubjectsPerACLEntry), nil
	})
	srv.handleRead(defaultEndpointID, accessControlClusterID, targetsPerAccessControlEntryAttrID, func() (func(enc tlv.Encoder) error, error) {
		return uint16Attribute(mockTargetsPerACLEntry), nil
	})
	srv.handleRead(defaultEndpointID, accessControlClusterID, accessControlEntriesPerFabricAttrID, func() (func(enc tlv.Encoder) error, error) {
		return uint16Attribute(mockACLEntriesPerFabric), nil
	})
}
