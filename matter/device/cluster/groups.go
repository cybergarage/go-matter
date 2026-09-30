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

package cluster

import (
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	"github.com/cybergarage/go-matter/matter/protocol/im"
)

// Groups cluster (Matter Application Cluster 1.3).
const (
	GroupsClusterID im.ClusterID = 0x0004

	NameSupportAttributeID im.AttributeID = 0x0000

	AddGroupCommandID              im.CommandID = 0x00
	ViewGroupCommandID             im.CommandID = 0x01
	GetGroupMembershipCommandID    im.CommandID = 0x02
	RemoveGroupCommandID           im.CommandID = 0x03
	RemoveAllGroupsCommandID       im.CommandID = 0x04
	AddGroupIfIdentifyingCommandID im.CommandID = 0x05

	groupsClusterRevision = 4
)

// Groups is the server of the Groups cluster for a node without group
// keys: since the Group Key Management cluster holds no group key set, no
// group can be added (1.3.7.1), and the endpoint belongs to none.
type Groups struct{}

// NewGroups returns a Groups cluster server.
func NewGroups() *Groups {
	return &Groups{}
}

// Register serves the cluster on ep.
func (c *Groups) Register(ep Endpoint) {
	ep.HandleAttribute(GroupsClusterID, NameSupportAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		enc.PutUnsigned1(tag, 0)
		return im.StatusSuccess
	})
	ep.HandleAttribute(GroupsClusterID, featureMapAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		enc.PutUnsigned4(tag, 0)
		return im.StatusSuccess
	})
	ep.HandleAttribute(GroupsClusterID, clusterRevisionAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		enc.PutUnsigned2(tag, groupsClusterRevision)
		return im.StatusSuccess
	})

	manage := im.WithPrivilege(im.PrivilegeManage)
	ep.HandleCommand(GroupsClusterID, AddGroupCommandID, func(req *im.CommandRequest) im.CommandResult {
		id, status := groupID(req)
		if status == im.StatusSuccess {
			status = im.StatusUnsupportedAccess
		}
		return groupStatusResponse(AddGroupCommandID, status, id, nil)
	}, manage, im.WithResponseCommand(AddGroupCommandID))
	ep.HandleCommand(GroupsClusterID, ViewGroupCommandID, func(req *im.CommandRequest) im.CommandResult {
		id, status := groupID(req)
		if status == im.StatusSuccess {
			status = im.StatusNotFound
		}
		name := ""
		return groupStatusResponse(ViewGroupCommandID, status, id, &name)
	}, im.WithResponseCommand(ViewGroupCommandID))
	ep.HandleCommand(GroupsClusterID, GetGroupMembershipCommandID, func(*im.CommandRequest) im.CommandResult {
		enc := tlv.NewEncoder()
		enc.BeginStructure(tlv.NewContextTag(1))
		enc.PutUnsigned1(tlv.NewContextTag(0), 0) // Capacity: no room
		enc.BeginArray(tlv.NewContextTag(1))
		if err := enc.EndContainer(); err != nil {
			return im.CommandStatus(im.StatusFailure)
		}
		if err := enc.EndContainer(); err != nil {
			return im.CommandStatus(im.StatusFailure)
		}
		return im.CommandResponse(GetGroupMembershipCommandID, enc.Bytes())
	}, im.WithResponseCommand(GetGroupMembershipCommandID))
	ep.HandleCommand(GroupsClusterID, RemoveGroupCommandID, func(req *im.CommandRequest) im.CommandResult {
		id, status := groupID(req)
		if status == im.StatusSuccess {
			status = im.StatusNotFound
		}
		return groupStatusResponse(RemoveGroupCommandID, status, id, nil)
	}, manage, im.WithResponseCommand(RemoveGroupCommandID))
	ep.HandleCommand(GroupsClusterID, RemoveAllGroupsCommandID, func(*im.CommandRequest) im.CommandResult {
		return im.CommandStatus(im.StatusSuccess)
	}, manage)
	ep.HandleCommand(GroupsClusterID, AddGroupIfIdentifyingCommandID, func(req *im.CommandRequest) im.CommandResult {
		_, status := groupID(req)
		if status == im.StatusSuccess {
			status = im.StatusUnsupportedAccess
		}
		return im.CommandStatus(status)
	}, manage)
}

// groupID returns the GroupID field of a command, CONSTRAINT_ERROR for
// the invalid group 0 (1.3.7.1).
func groupID(req *im.CommandRequest) (uint16, im.Status) {
	v, ok := unsignedField(req, 0)
	if !ok || 0xFFFF < v {
		return 0, im.StatusInvalidCommand
	}
	if v == 0 {
		return 0, im.StatusConstraintError
	}
	return uint16(v), im.StatusSuccess
}

// groupStatusResponse encodes the {Status, GroupID[, GroupName]} fields of
// a Groups response command.
func groupStatusResponse(cmd im.CommandID, status im.Status, id uint16, name *string) im.CommandResult {
	if status == im.StatusInvalidCommand {
		return im.CommandStatus(status)
	}
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewContextTag(1))
	enc.PutUnsigned1(tlv.NewContextTag(0), uint8(status))
	enc.PutUnsigned2(tlv.NewContextTag(1), id)
	if name != nil {
		if err := enc.PutUTF81(tlv.NewContextTag(2), *name); err != nil {
			return im.CommandStatus(im.StatusFailure)
		}
	}
	if err := enc.EndContainer(); err != nil {
		return im.CommandStatus(im.StatusFailure)
	}
	return im.CommandResponse(cmd, enc.Bytes())
}
