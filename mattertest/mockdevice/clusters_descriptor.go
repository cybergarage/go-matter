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

// Descriptor cluster (0x001D) attribute IDs, per Matter Core Spec 9.5.5.
const (
	descriptorClusterID       im.ClusterID   = 0x001D
	deviceTypeListAttributeID im.AttributeID = 0x0000
	serverListAttributeID     im.AttributeID = 0x0001
	clientListAttributeID     im.AttributeID = 0x0002
	partsListAttributeID      im.AttributeID = 0x0003

	// rootNodeDeviceTypeID/rootNodeDeviceTypeRevision are the Root Node
	// device type this mock's single endpoint (0) reports, per the Device
	// Library's Root Node device type definition.
	rootNodeDeviceTypeID       uint32 = 0x0016
	rootNodeDeviceTypeRevision uint16 = 1
)

// operationalServerClusterIDs lists every cluster this mock device serves
// operationally (over CASE, once commissioned) — the single source of
// truth for Descriptor's ServerList, kept here so it can't silently drift
// from what registerCASEHandlers actually wires up. Update this whenever a
// new registerXHandlers call is added there.
var operationalServerClusterIDs = []im.ClusterID{
	generalCommissioningClusterID,
	descriptorClusterID,
	basicInformationClusterID,
	accessControlClusterID,
	generalDiagnosticsClusterID,
}

// registerDescriptorHandlers wires read-only access to DeviceTypeList,
// ServerList, ClientList and PartsList into srv. This mock has a single
// endpoint (0, the Root Node), so ClientList and PartsList are always
// empty.
func registerDescriptorHandlers(srv *imServer, d *Device) {
	srv.handleRead(defaultEndpointID, descriptorClusterID, deviceTypeListAttributeID, func() (func(enc tlv.Encoder) error, error) {
		return listAttribute(func(enc tlv.Encoder) error {
			enc.BeginStructure(tlv.NewAnonymousTag())
			enc.PutUnsigned4(tlv.NewContextTag(0), rootNodeDeviceTypeID)
			enc.PutUnsigned2(tlv.NewContextTag(1), rootNodeDeviceTypeRevision)
			return enc.EndContainer()
		}), nil
	})

	srv.handleRead(defaultEndpointID, descriptorClusterID, serverListAttributeID, func() (func(enc tlv.Encoder) error, error) {
		return listAttribute(func(enc tlv.Encoder) error {
			for _, cl := range operationalServerClusterIDs {
				if err := enc.PutUnsigned(tlv.NewAnonymousTag(), uint64(cl)); err != nil {
					return err
				}
			}
			return nil
		}), nil
	})

	srv.handleRead(defaultEndpointID, descriptorClusterID, clientListAttributeID, func() (func(enc tlv.Encoder) error, error) {
		return listAttribute(func(enc tlv.Encoder) error { return nil }), nil
	})

	srv.handleRead(defaultEndpointID, descriptorClusterID, partsListAttributeID, func() (func(enc tlv.Encoder) error, error) {
		return listAttribute(func(enc tlv.Encoder) error { return nil }), nil
	})
}
