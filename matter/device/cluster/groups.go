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
	"slices"

	"github.com/cybergarage/go-matter/matter/device"
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

	// GroupsFeatureGroupNames is the GroupNames feature (GN).
	GroupsFeatureGroupNames uint32 = 0x01
	// nameSupportGroupNames is the NameSupport bit of group names.
	nameSupportGroupNames = 0x80

	groupsClusterRevision = 4
)

// GroupEndpoint is an endpoint which can join the groups of a fabric that
// the Group Key Management cluster maps keys to; *device.Endpoint is one.
type GroupEndpoint interface {
	FabricEndpoint
	JoinGroup(fabricIndex uint8, groupID uint16, name string) im.Status
	LeaveGroup(fabricIndex uint8, groupID uint16) im.Status
	LeaveAllGroups(fabricIndex uint8) []uint16
	Groups(fabricIndex uint8) []device.GroupMembership
	GroupCapacity(fabricIndex uint8) int
}

// Groups is the server of the Groups cluster with group names: it puts
// the endpoint in the groups of the accessing fabric, which the Group Key
// Management cluster keeps.
type Groups struct {
	endpoint      GroupEndpoint
	identify      *Identify
	groupsRemoved func(fabricIndex uint8, groupIDs []uint16)
}

// GroupsOption configures a Groups.
type GroupsOption func(*Groups)

// WithGroupsIdentify makes AddGroupIfIdentifying add a group while the
// endpoint's Identify identifies.
func WithGroupsIdentify(identify *Identify) GroupsOption {
	return func(c *Groups) {
		c.identify = identify
	}
}

// WithGroupsRemovedHandler sets the function called with the groups the
// endpoint leaves, such as Scenes.RemoveGroups, whose scenes go with them.
func WithGroupsRemovedHandler(h func(fabricIndex uint8, groupIDs []uint16)) GroupsOption {
	return func(c *Groups) {
		c.groupsRemoved = h
	}
}

// NewGroups returns a Groups cluster server.
func NewGroups(opts ...GroupsOption) *Groups {
	c := &Groups{endpoint: nil, identify: nil, groupsRemoved: nil}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Register serves the cluster on ep.
func (c *Groups) Register(ep GroupEndpoint) {
	c.endpoint = ep
	ep.HandleAttribute(GroupsClusterID, NameSupportAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		enc.PutUnsigned1(tag, nameSupportGroupNames)
		return im.StatusSuccess
	})
	ep.HandleAttribute(GroupsClusterID, featureMapAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		enc.PutUnsigned4(tag, GroupsFeatureGroupNames)
		return im.StatusSuccess
	})
	ep.HandleAttribute(GroupsClusterID, clusterRevisionAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		enc.PutUnsigned2(tag, groupsClusterRevision)
		return im.StatusSuccess
	})

	manage := im.WithPrivilege(im.PrivilegeManage)
	ep.HandleCommand(GroupsClusterID, AddGroupCommandID, c.addGroup, manage, im.WithResponseCommand(AddGroupCommandID))
	ep.HandleCommand(GroupsClusterID, ViewGroupCommandID, c.viewGroup, im.WithResponseCommand(ViewGroupCommandID))
	ep.HandleCommand(GroupsClusterID, GetGroupMembershipCommandID, c.getGroupMembership, im.WithResponseCommand(GetGroupMembershipCommandID))
	ep.HandleCommand(GroupsClusterID, RemoveGroupCommandID, c.removeGroup, manage, im.WithResponseCommand(RemoveGroupCommandID))
	ep.HandleCommand(GroupsClusterID, RemoveAllGroupsCommandID, c.removeAllGroups, manage)
	ep.HandleCommand(GroupsClusterID, AddGroupIfIdentifyingCommandID, c.addGroupIfIdentifying, manage)
}

// groupID returns the GroupID field of a command, CONSTRAINT_ERROR for
// group 0, which is no group.
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

// groupName returns the GroupName field of a command.
func groupName(req *im.CommandRequest) (string, im.Status) {
	field, ok := req.Field(1)
	if !ok {
		return "", im.StatusInvalidCommand
	}
	name, ok := field.UTF8()
	if !ok {
		return "", im.StatusInvalidCommand
	}
	if device.MaxGroupNameLength < len(name) {
		return "", im.StatusConstraintError
	}
	return name, im.StatusSuccess
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
		if err := enc.PutUTF8(tlv.NewContextTag(2), *name); err != nil {
			return im.CommandStatus(im.StatusFailure)
		}
	}
	if err := enc.EndContainer(); err != nil {
		return im.CommandStatus(im.StatusFailure)
	}
	return im.CommandResponse(cmd, enc.Bytes())
}

// add puts the endpoint in the group a command names, for addGroup and
// addGroupIfIdentifying.
func (c *Groups) add(req *im.CommandRequest) (uint16, im.Status) {
	id, status := groupID(req)
	if status != im.StatusSuccess {
		return id, status
	}
	name, status := groupName(req)
	if status != im.StatusSuccess {
		return id, status
	}
	fabric := c.endpoint.AccessingFabric(req.Session)
	if fabric == 0 {
		return id, im.StatusUnsupportedAccess
	}
	return id, c.endpoint.JoinGroup(fabric, id, name)
}

// addGroup handles AddGroup: the accessing fabric must have mapped the
// group to a key set.
func (c *Groups) addGroup(req *im.CommandRequest) im.CommandResult {
	id, status := c.add(req)
	return groupStatusResponse(AddGroupCommandID, status, id, nil)
}

// addGroupIfIdentifying handles AddGroupIfIdentifying: AddGroup while the
// endpoint identifies, and nothing otherwise.
func (c *Groups) addGroupIfIdentifying(req *im.CommandRequest) im.CommandResult {
	if c.identify == nil || c.identify.IdentifyTime() == 0 {
		if _, status := groupID(req); status != im.StatusSuccess {
			return im.CommandStatus(status)
		}
		return im.CommandStatus(im.StatusSuccess)
	}
	_, status := c.add(req)
	return im.CommandStatus(status)
}

// viewGroup handles ViewGroup.
func (c *Groups) viewGroup(req *im.CommandRequest) im.CommandResult {
	id, status := groupID(req)
	if status != im.StatusSuccess {
		return groupStatusResponse(ViewGroupCommandID, status, id, new(string))
	}
	fabric := c.endpoint.AccessingFabric(req.Session)
	for _, g := range c.endpoint.Groups(fabric) {
		if g.GroupID == id {
			return groupStatusResponse(ViewGroupCommandID, im.StatusSuccess, id, &g.Name)
		}
	}
	return groupStatusResponse(ViewGroupCommandID, im.StatusNotFound, id, new(string))
}

// getGroupMembership handles GetGroupMembership: the groups of the
// accessing fabric the endpoint is in, all of them or those of the
// GroupList, and how many more it can join.
func (c *Groups) getGroupMembership(req *im.CommandRequest) im.CommandResult {
	fabric := c.endpoint.AccessingFabric(req.Session)
	var asked []uint16
	dec, err := req.Decoder()
	if err != nil {
		return im.CommandStatus(im.StatusInvalidCommand)
	}
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			break
		}
		if tag, _ := contextTag(elem); tag == 0 && elem.Type().IsArray() {
			for dec.Next() {
				item := dec.Element()
				if item.Type().IsEndOfContainer() {
					break
				}
				v, ok := item.Unsigned()
				if !ok || 0xFFFF < v {
					return im.CommandStatus(im.StatusInvalidCommand)
				}
				asked = append(asked, uint16(v))
			}
		} else if elem.Type().IsContainer() {
			if err := skipContainer(dec); err != nil {
				return im.CommandStatus(im.StatusInvalidCommand)
			}
		}
	}
	var groups []uint16
	for _, g := range c.endpoint.Groups(fabric) {
		if len(asked) == 0 || slices.Contains(asked, g.GroupID) {
			groups = append(groups, g.GroupID)
		}
	}
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewContextTag(1))
	enc.PutUnsigned1(tlv.NewContextTag(0), uint8(min(c.endpoint.GroupCapacity(fabric), 0xFE))) // nolint: gosec // bounded above
	enc.BeginArray(tlv.NewContextTag(1))
	for _, g := range groups {
		enc.PutUnsigned2(tlv.NewAnonymousTag(), g)
	}
	if err := enc.EndContainer(); err != nil {
		return im.CommandStatus(im.StatusFailure)
	}
	if err := enc.EndContainer(); err != nil {
		return im.CommandStatus(im.StatusFailure)
	}
	return im.CommandResponse(GetGroupMembershipCommandID, enc.Bytes())
}

// removeGroup handles RemoveGroup.
func (c *Groups) removeGroup(req *im.CommandRequest) im.CommandResult {
	id, status := groupID(req)
	fabric := c.endpoint.AccessingFabric(req.Session)
	if fabric == 0 {
		return im.CommandStatus(im.StatusUnsupportedAccess)
	}
	if status == im.StatusSuccess {
		status = c.endpoint.LeaveGroup(fabric, id)
		if status == im.StatusSuccess && c.groupsRemoved != nil {
			c.groupsRemoved(fabric, []uint16{id})
		}
	}
	return groupStatusResponse(RemoveGroupCommandID, status, id, nil)
}

// removeAllGroups handles RemoveAllGroups.
func (c *Groups) removeAllGroups(req *im.CommandRequest) im.CommandResult {
	fabric := c.endpoint.AccessingFabric(req.Session)
	left := c.endpoint.LeaveAllGroups(fabric)
	if 0 < len(left) && c.groupsRemoved != nil {
		c.groupsRemoved(fabric, left)
	}
	return im.CommandStatus(im.StatusSuccess)
}
