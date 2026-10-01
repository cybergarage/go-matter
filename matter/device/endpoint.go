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

package device

import (
	"errors"
	"fmt"
	"slices"

	"github.com/cybergarage/go-matter/matter/protocol/im"
	"github.com/cybergarage/go-matter/matter/store"
)

var (
	// ErrEndpointReserved is returned when an application asks for the
	// root endpoint, which the device itself serves.
	ErrEndpointReserved = errors.New("device: endpoint 0 is the root node's")
	// ErrEndpointExists is returned when an endpoint is added twice.
	ErrEndpointExists = errors.New("device: the endpoint already exists")
	// ErrNoDeviceType is returned when an endpoint is added without a
	// device type.
	ErrNoDeviceType = errors.New("device: an endpoint needs a device type")
)

// Endpoint is an application endpoint of a device, such as the light of
// an On/Off Light (Matter Core 9.2). It carries the Descriptor cluster
// with its device types; the application registers the clusters its
// device types require on it.
type Endpoint struct {
	id     im.EndpointID
	server *im.Server
	device *Device
}

// AddEndpoint adds an application endpoint conforming to deviceTypes. The
// root endpoint lists it in its PartsList.
func (d *Device) AddEndpoint(id im.EndpointID, deviceTypes ...DeviceType) (*Endpoint, error) {
	if id == rootEndpoint {
		return nil, ErrEndpointReserved
	}
	if len(deviceTypes) == 0 {
		return nil, ErrNoDeviceType
	}
	if !d.descriptors.addNew(id, deviceTypes...) {
		return nil, fmt.Errorf("%w: %d", ErrEndpointExists, id)
	}
	d.imServer.NotifyAttributeChanged(im.AttributePath{Endpoint: rootEndpoint, Cluster: DescriptorClusterID, Attribute: partsListAttributeID})
	return &Endpoint{id: id, server: d.imServer, device: d}, nil
}

// ID returns the endpoint's number.
func (ep *Endpoint) ID() im.EndpointID {
	return ep.id
}

// HandleAttribute serves a readable attribute of a cluster on the
// endpoint.
func (ep *Endpoint) HandleAttribute(cluster im.ClusterID, attribute im.AttributeID, r im.AttributeReader, opts ...im.HandlerOption) {
	ep.server.HandleAttribute(ep.id, cluster, attribute, r, opts...)
}

// HandleAttributeRead serves a readable attribute whose value depends on
// the request, such as a fabric-scoped one.
func (ep *Endpoint) HandleAttributeRead(cluster im.ClusterID, attribute im.AttributeID, h im.AttributeReadHandler, opts ...im.HandlerOption) {
	ep.server.HandleAttributeRead(ep.id, cluster, attribute, h, opts...)
}

// HandleAttributeWrite makes an attribute writable.
func (ep *Endpoint) HandleAttributeWrite(cluster im.ClusterID, attribute im.AttributeID, h im.AttributeWriteHandler, opts ...im.HandlerOption) {
	ep.server.HandleAttributeWrite(ep.id, cluster, attribute, h, opts...)
}

// HandleCommand serves a command of a cluster on the endpoint.
func (ep *Endpoint) HandleCommand(cluster im.ClusterID, command im.CommandID, h im.CommandHandler, opts ...im.HandlerOption) {
	ep.server.HandleCommand(ep.id, cluster, command, h, opts...)
}

// NotifyAttributeChanged reports a changed attribute to the subscriptions
// which cover it. An application calls it whenever an attribute changes
// other than by a write, such as by a command or by the hardware.
func (ep *Endpoint) NotifyAttributeChanged(cluster im.ClusterID, attribute im.AttributeID) {
	ep.server.NotifyAttributeChanged(im.AttributePath{Endpoint: ep.id, Cluster: cluster, Attribute: attribute})
}

// AccessingFabric returns the fabric index a session accesses the device
// on, which a fabric-scoped command or attribute acts for, or 0 for a
// session on no fabric yet.
func (ep *Endpoint) AccessingFabric(sess im.SecureSession) uint8 {
	return ep.device.lookupSession(sess).fabricIndex
}

// HandleFabricRemoved registers h to be called with the index of each
// fabric RemoveFabric removes, for the fabric-scoped data a cluster keeps
// to be removed with it.
func (ep *Endpoint) HandleFabricRemoved(h func(fabricIndex uint8)) {
	ep.device.mu.Lock()
	defer ep.device.mu.Unlock()
	ep.device.fabricRemovedHandlers = append(ep.device.fabricRemovedHandlers, h)
}

// GroupMembership is a group an endpoint is in, with the name it was
// added with.
type GroupMembership struct {
	GroupID uint16
	Name    string
}

func (ep *Endpoint) groupTableChanged() {
	ep.server.NotifyAttributeChanged(im.AttributePath{Endpoint: rootEndpoint, Cluster: GroupKeyManagementClusterID, Attribute: groupTableAttributeID})
}

// JoinGroup puts the endpoint in a group of a fabric, as the Groups
// cluster's AddGroup does, or renames the group it is in already. The
// fabric must have mapped the group to a key set (UNSUPPORTED_ACCESS
// otherwise), and may be in MaxGroupsPerFabric groups (RESOURCE_EXHAUSTED
// beyond).
func (ep *Endpoint) JoinGroup(fabricIndex uint8, groupID uint16, name string) im.Status {
	status := ep.device.groupKeys.update(fabricIndex, func(rec *store.GroupKeysRecord) im.Status {
		if !slices.ContainsFunc(rec.KeyMap, func(e store.GroupKeyMapEntry) bool { return e.GroupID == groupID }) {
			return im.StatusUnsupportedAccess
		}
		endpoint := uint16(ep.id)
		for i := range rec.Groups {
			if rec.Groups[i].GroupID != groupID {
				continue
			}
			rec.Groups[i].Name = name
			if !slices.Contains(rec.Groups[i].Endpoints, endpoint) {
				rec.Groups[i].Endpoints = append(rec.Groups[i].Endpoints, endpoint)
				slices.Sort(rec.Groups[i].Endpoints)
			}
			return im.StatusSuccess
		}
		if MaxGroupsPerFabric <= len(rec.Groups) {
			return im.StatusResourceExhausted
		}
		rec.Groups = append(rec.Groups, store.GroupRecord{GroupID: groupID, Name: name, Endpoints: []uint16{endpoint}})
		return im.StatusSuccess
	})
	if status == im.StatusSuccess {
		ep.groupTableChanged()
	}
	return status
}

// LeaveGroup takes the endpoint out of a group of a fabric, as the Groups
// cluster's RemoveGroup does; NOT_FOUND when it is not in it.
func (ep *Endpoint) LeaveGroup(fabricIndex uint8, groupID uint16) im.Status {
	status := ep.device.groupKeys.update(fabricIndex, func(rec *store.GroupKeysRecord) im.Status {
		if !leaveGroup(rec, uint16(ep.id), func(g uint16) bool { return g == groupID }) {
			return im.StatusNotFound
		}
		return im.StatusSuccess
	})
	if status == im.StatusSuccess {
		ep.groupTableChanged()
	}
	return status
}

// LeaveAllGroups takes the endpoint out of every group of a fabric, as the
// Groups cluster's RemoveAllGroups does, and returns the groups it left.
func (ep *Endpoint) LeaveAllGroups(fabricIndex uint8) []uint16 {
	groups := ep.Groups(fabricIndex)
	left := make([]uint16, 0, len(groups))
	for _, g := range groups {
		left = append(left, g.GroupID)
	}
	if len(left) == 0 {
		return nil
	}
	ep.device.groupKeys.update(fabricIndex, func(rec *store.GroupKeysRecord) im.Status {
		leaveGroup(rec, uint16(ep.id), func(uint16) bool { return true })
		return im.StatusSuccess
	})
	ep.groupTableChanged()
	return left
}

// leaveGroup removes endpoint from the groups match selects, and the
// groups no endpoint is left in, and reports whether it was in any.
func leaveGroup(rec *store.GroupKeysRecord, endpoint uint16, match func(groupID uint16) bool) bool {
	found := false
	groups := rec.Groups[:0]
	for _, g := range rec.Groups {
		if match(g.GroupID) {
			if i := slices.Index(g.Endpoints, endpoint); 0 <= i {
				g.Endpoints = slices.Delete(g.Endpoints, i, i+1)
				found = true
			}
		}
		if 0 < len(g.Endpoints) {
			groups = append(groups, g)
		}
	}
	rec.Groups = groups
	return found
}

// Groups returns the groups of a fabric the endpoint is in.
func (ep *Endpoint) Groups(fabricIndex uint8) []GroupMembership {
	rec, err := ep.device.groupKeys.load(fabricIndex)
	if err != nil {
		return nil
	}
	var groups []GroupMembership
	for _, g := range rec.Groups {
		if slices.Contains(g.Endpoints, uint16(ep.id)) {
			groups = append(groups, GroupMembership{GroupID: g.GroupID, Name: g.Name})
		}
	}
	return groups
}

// GroupCapacity returns how many more groups a fabric can put the
// endpoint in.
func (ep *Endpoint) GroupCapacity(fabricIndex uint8) int {
	rec, err := ep.device.groupKeys.load(fabricIndex)
	if err != nil {
		return 0
	}
	return max(0, MaxGroupsPerFabric-len(rec.Groups))
}
