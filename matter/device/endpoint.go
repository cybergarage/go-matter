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

	"github.com/cybergarage/go-matter/matter/protocol/im"
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
