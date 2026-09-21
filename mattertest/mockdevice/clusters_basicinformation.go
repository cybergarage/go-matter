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

// Basic Information cluster (0x0028) attribute IDs, per Matter Core Spec
// 11.1.6.
const (
	basicInformationClusterID im.ClusterID   = 0x0028
	dataModelRevisionAttrID   im.AttributeID = 0x0000
	vendorIDAttrID            im.AttributeID = 0x0002
	productIDAttrID           im.AttributeID = 0x0004
	hardwareVersionAttrID     im.AttributeID = 0x0007
	softwareVersionAttrID     im.AttributeID = 0x0009

	mockDataModelRevision uint16 = 19 // Matter 1.5's Data Model revision.
	mockHardwareVersion   uint16 = 1
	mockSoftwareVersion   uint32 = 1
)

// registerBasicInformationHandlers wires read-only access to
// DataModelRevision, VendorID, ProductID, HardwareVersion and
// SoftwareVersion into srv. VendorID/ProductID are sourced from d's own
// configured identity, letting a test assert them against the values it
// passed to mockdevice.New.
func registerBasicInformationHandlers(srv *imServer, d *Device) {
	srv.handleRead(defaultEndpointID, basicInformationClusterID, dataModelRevisionAttrID, func() (func(enc tlv.Encoder) error, error) {
		return uint16Attribute(mockDataModelRevision), nil
	})
	srv.handleRead(defaultEndpointID, basicInformationClusterID, vendorIDAttrID, func() (func(enc tlv.Encoder) error, error) {
		return uint16Attribute(d.VendorID()), nil
	})
	srv.handleRead(defaultEndpointID, basicInformationClusterID, productIDAttrID, func() (func(enc tlv.Encoder) error, error) {
		return uint16Attribute(d.ProductID()), nil
	})
	srv.handleRead(defaultEndpointID, basicInformationClusterID, hardwareVersionAttrID, func() (func(enc tlv.Encoder) error, error) {
		return uint16Attribute(mockHardwareVersion), nil
	})
	srv.handleRead(defaultEndpointID, basicInformationClusterID, softwareVersionAttrID, func() (func(enc tlv.Encoder) error, error) {
		return uint32Attribute(mockSoftwareVersion), nil
	})
}
