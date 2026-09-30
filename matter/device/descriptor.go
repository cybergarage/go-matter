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
	"slices"
	"sync"

	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	"github.com/cybergarage/go-matter/matter/protocol/im"
)

// Descriptor cluster (Matter Core 9.5).
const (
	DescriptorClusterID im.ClusterID = 0x001D

	deviceTypeListAttributeID im.AttributeID = 0x0000
	serverListAttributeID     im.AttributeID = 0x0001
	clientListAttributeID     im.AttributeID = 0x0002
	partsListAttributeID      im.AttributeID = 0x0003

	descriptorClusterRevision = 2
)

// DeviceType is a device type an endpoint conforms to, with the revision
// of its definition it implements (Matter Device Library).
type DeviceType struct {
	ID       uint32
	Revision uint16
}

// RootNodeDeviceType is the device type of endpoint 0, which carries the
// node's utility clusters (Matter Device Library 2.1).
var RootNodeDeviceType = DeviceType{ID: 0x0016, Revision: 3}

// OnOffLightDeviceType is a light that can be switched on and off, with
// the Identify, Groups and On/Off clusters (Matter Device Library 4.1).
var OnOffLightDeviceType = DeviceType{ID: 0x0100, Revision: 3}

// descriptors keeps the device types of each endpoint and serves the
// Descriptor cluster on it. The server and parts lists are derived from
// what the IM server has registered, so they follow the clusters and the
// endpoints the application adds.
type descriptors struct {
	mutex       sync.Mutex
	server      *im.Server
	deviceTypes map[im.EndpointID][]DeviceType
}

func newDescriptors(server *im.Server) *descriptors {
	return &descriptors{
		mutex:       sync.Mutex{},
		server:      server,
		deviceTypes: map[im.EndpointID][]DeviceType{},
	}
}

// addNew registers the Descriptor cluster on endpoint with its device
// types, unless the endpoint already has one.
func (ds *descriptors) addNew(endpoint im.EndpointID, deviceTypes ...DeviceType) bool {
	ds.mutex.Lock()
	_, exists := ds.deviceTypes[endpoint]
	if !exists {
		ds.deviceTypes[endpoint] = append([]DeviceType(nil), deviceTypes...)
	}
	ds.mutex.Unlock()
	if exists {
		return false
	}
	ds.register(endpoint)
	return true
}

// add registers the Descriptor cluster on endpoint with its device types.
func (ds *descriptors) add(endpoint im.EndpointID, deviceTypes ...DeviceType) {
	ds.mutex.Lock()
	ds.deviceTypes[endpoint] = append([]DeviceType(nil), deviceTypes...)
	ds.mutex.Unlock()
	ds.register(endpoint)
}

// register serves the Descriptor cluster on endpoint.
func (ds *descriptors) register(endpoint im.EndpointID) {
	ds.server.HandleAttribute(endpoint, DescriptorClusterID, deviceTypeListAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		ds.mutex.Lock()
		types := ds.deviceTypes[endpoint]
		ds.mutex.Unlock()
		enc.BeginArray(tag)
		for _, dt := range types {
			enc.BeginStructure(tlv.NewAnonymousTag())
			enc.PutUnsigned4(tlv.NewContextTag(0), dt.ID)
			enc.PutUnsigned2(tlv.NewContextTag(1), dt.Revision)
			if err := enc.EndContainer(); err != nil {
				return im.StatusFailure
			}
		}
		if err := enc.EndContainer(); err != nil {
			return im.StatusFailure
		}
		return im.StatusSuccess
	})
	ds.server.HandleAttribute(endpoint, DescriptorClusterID, serverListAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		ids := ds.server.Clusters(endpoint)
		return encodeUint32List(enc, tag, len(ids), func(i int) uint32 { return uint32(ids[i]) })
	})
	ds.server.HandleAttribute(endpoint, DescriptorClusterID, clientListAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		return encodeUint32List(enc, tag, 0, nil)
	})
	ds.server.HandleAttribute(endpoint, DescriptorClusterID, partsListAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		parts := ds.parts(endpoint)
		return encodeUint32List(enc, tag, len(parts), func(i int) uint32 { return uint32(parts[i]) })
	})
	ds.server.HandleAttribute(endpoint, DescriptorClusterID, featureMapAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		enc.PutUnsigned4(tag, 0)
		return im.StatusSuccess
	})
	ds.server.HandleAttribute(endpoint, DescriptorClusterID, clusterRevisionAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		enc.PutUnsigned2(tag, descriptorClusterRevision)
		return im.StatusSuccess
	})
}

// hasDeviceType reports whether an endpoint is of a device type.
func (ds *descriptors) hasDeviceType(endpoint im.EndpointID, id uint32) bool {
	ds.mutex.Lock()
	defer ds.mutex.Unlock()
	for _, dt := range ds.deviceTypes[endpoint] {
		if dt.ID == id {
			return true
		}
	}
	return false
}

// parts returns an endpoint's PartsList: for the root endpoint every
// other endpoint with a Descriptor, and for the others none, since the
// device composes its endpoints flat under the root (9.5.6.4).
func (ds *descriptors) parts(endpoint im.EndpointID) []im.EndpointID {
	if endpoint != rootEndpoint {
		return nil
	}
	ds.mutex.Lock()
	defer ds.mutex.Unlock()
	parts := make([]im.EndpointID, 0, len(ds.deviceTypes))
	for ep := range ds.deviceTypes {
		if ep != rootEndpoint {
			parts = append(parts, ep)
		}
	}
	slices.Sort(parts)
	return parts
}

func encodeUint32List(enc tlv.Encoder, tag tlv.Tag, n int, item func(int) uint32) im.Status {
	enc.BeginArray(tag)
	for i := range n {
		if err := enc.PutUnsigned(tlv.NewAnonymousTag(), uint64(item(i))); err != nil {
			return im.StatusFailure
		}
	}
	if err := enc.EndContainer(); err != nil {
		return im.StatusFailure
	}
	return im.StatusSuccess
}
