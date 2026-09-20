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

// Package basicinformation provides a client for the Matter Basic Information cluster (0x0028).
// Reference: Matter Core Spec 1.5, Section 11.1.
package basicinformation

import (
	"fmt"

	"github.com/cybergarage/go-matter/matter/protocol/im"
	"github.com/cybergarage/go-matter/matter/protocol/session"
)

// ClusterID is the Basic Information cluster identifier.
// 11.1. Basic Information Cluster.
const ClusterID im.ClusterID = 0x0028

// Attribute IDs for the Basic Information cluster.
// 11.1.6. Attributes.
const (
	// DataModelRevisionAttributeID reports the Data Model revision the device implements.
	DataModelRevisionAttributeID im.AttributeID = 0x0000
	// VendorNameAttributeID reports the human-readable vendor name.
	VendorNameAttributeID im.AttributeID = 0x0001
	// VendorIDAttributeID reports the vendor identifier.
	// 2.5.2. Vendor Identifier (Vendor ID, VID).
	VendorIDAttributeID im.AttributeID = 0x0002
	// ProductNameAttributeID reports the human-readable product name.
	ProductNameAttributeID im.AttributeID = 0x0003
	// ProductIDAttributeID reports the product identifier.
	// 2.5.3. Product Identifier (Product ID, PID).
	ProductIDAttributeID im.AttributeID = 0x0004
	// NodeLabelAttributeID reports the user-assigned label for this node.
	NodeLabelAttributeID im.AttributeID = 0x0005
	// LocationAttributeID reports the IEC 60304 country/region code the device is set to.
	LocationAttributeID im.AttributeID = 0x0006
	// HardwareVersionAttributeID reports the hardware version.
	HardwareVersionAttributeID im.AttributeID = 0x0007
	// HardwareVersionStringAttributeID reports the human-readable hardware version.
	HardwareVersionStringAttributeID im.AttributeID = 0x0008
	// SoftwareVersionAttributeID reports the software version.
	SoftwareVersionAttributeID im.AttributeID = 0x0009
	// SoftwareVersionStringAttributeID reports the human-readable software version.
	SoftwareVersionStringAttributeID im.AttributeID = 0x000A
	// SerialNumberAttributeID reports the device's serial number.
	SerialNumberAttributeID im.AttributeID = 0x000F
	// UniqueIDAttributeID reports a per-device identifier unique across the vendor's device instances.
	UniqueIDAttributeID im.AttributeID = 0x0012
)

// DataModelRevision reads the DataModelRevision attribute of the given endpoint.
func DataModelRevision(sess session.SecureSession, endpointID im.EndpointID) (uint16, error) {
	return readUint16Attribute(sess, endpointID, DataModelRevisionAttributeID, "DataModelRevision")
}

// VendorName reads the VendorName attribute of the given endpoint.
func VendorName(sess session.SecureSession, endpointID im.EndpointID) (string, error) {
	return readUTF8Attribute(sess, endpointID, VendorNameAttributeID, "VendorName")
}

// VendorID reads the VendorID attribute of the given endpoint.
// 2.5.2. Vendor Identifier (Vendor ID, VID).
func VendorID(sess session.SecureSession, endpointID im.EndpointID) (uint16, error) {
	return readUint16Attribute(sess, endpointID, VendorIDAttributeID, "VendorID")
}

// ProductName reads the ProductName attribute of the given endpoint.
func ProductName(sess session.SecureSession, endpointID im.EndpointID) (string, error) {
	return readUTF8Attribute(sess, endpointID, ProductNameAttributeID, "ProductName")
}

// ProductID reads the ProductID attribute of the given endpoint.
// 2.5.3. Product Identifier (Product ID, PID).
func ProductID(sess session.SecureSession, endpointID im.EndpointID) (uint16, error) {
	return readUint16Attribute(sess, endpointID, ProductIDAttributeID, "ProductID")
}

// NodeLabel reads the NodeLabel attribute of the given endpoint.
func NodeLabel(sess session.SecureSession, endpointID im.EndpointID) (string, error) {
	return readUTF8Attribute(sess, endpointID, NodeLabelAttributeID, "NodeLabel")
}

// Location reads the Location attribute of the given endpoint.
func Location(sess session.SecureSession, endpointID im.EndpointID) (string, error) {
	return readUTF8Attribute(sess, endpointID, LocationAttributeID, "Location")
}

// HardwareVersion reads the HardwareVersion attribute of the given endpoint.
func HardwareVersion(sess session.SecureSession, endpointID im.EndpointID) (uint16, error) {
	return readUint16Attribute(sess, endpointID, HardwareVersionAttributeID, "HardwareVersion")
}

// HardwareVersionString reads the HardwareVersionString attribute of the given endpoint.
func HardwareVersionString(sess session.SecureSession, endpointID im.EndpointID) (string, error) {
	return readUTF8Attribute(sess, endpointID, HardwareVersionStringAttributeID, "HardwareVersionString")
}

// SoftwareVersion reads the SoftwareVersion attribute of the given endpoint.
func SoftwareVersion(sess session.SecureSession, endpointID im.EndpointID) (uint32, error) {
	return readUint32Attribute(sess, endpointID, SoftwareVersionAttributeID, "SoftwareVersion")
}

// SoftwareVersionString reads the SoftwareVersionString attribute of the given endpoint.
func SoftwareVersionString(sess session.SecureSession, endpointID im.EndpointID) (string, error) {
	return readUTF8Attribute(sess, endpointID, SoftwareVersionStringAttributeID, "SoftwareVersionString")
}

// SerialNumber reads the SerialNumber attribute of the given endpoint.
func SerialNumber(sess session.SecureSession, endpointID im.EndpointID) (string, error) {
	return readUTF8Attribute(sess, endpointID, SerialNumberAttributeID, "SerialNumber")
}

// UniqueID reads the UniqueID attribute of the given endpoint.
func UniqueID(sess session.SecureSession, endpointID im.EndpointID) (string, error) {
	return readUTF8Attribute(sess, endpointID, UniqueIDAttributeID, "UniqueID")
}

// readUTF8Attribute reads a single UTF-8 string attribute of this cluster.
func readUTF8Attribute(sess session.SecureSession, endpointID im.EndpointID, attributeID im.AttributeID, name string) (string, error) {
	resp, err := im.ReadAttribute(sess, endpointID, ClusterID, attributeID)
	if err != nil {
		return "", fmt.Errorf("basicinformation: %s: %w", name, err)
	}
	if resp.Status != nil {
		return "", fmt.Errorf("basicinformation: %s failed: IM status 0x%02X, cluster status 0x%02X",
			name, resp.Status.IMStatus, resp.Status.ClusterStatus)
	}
	if resp.Value == nil {
		return "", fmt.Errorf("basicinformation: %s: ReadResponse missing attribute value", name)
	}
	v, ok := resp.Value.UTF8()
	if !ok {
		return "", fmt.Errorf("basicinformation: %s: attribute value is not a UTF-8 string", name)
	}
	return v, nil
}

// readUint16Attribute reads a single UINT16 attribute of this cluster.
func readUint16Attribute(sess session.SecureSession, endpointID im.EndpointID, attributeID im.AttributeID, name string) (uint16, error) {
	resp, err := im.ReadAttribute(sess, endpointID, ClusterID, attributeID)
	if err != nil {
		return 0, fmt.Errorf("basicinformation: %s: %w", name, err)
	}
	if resp.Status != nil {
		return 0, fmt.Errorf("basicinformation: %s failed: IM status 0x%02X, cluster status 0x%02X",
			name, resp.Status.IMStatus, resp.Status.ClusterStatus)
	}
	if resp.Value == nil {
		return 0, fmt.Errorf("basicinformation: %s: ReadResponse missing attribute value", name)
	}
	v, ok := resp.Value.Unsigned2()
	if !ok {
		return 0, fmt.Errorf("basicinformation: %s: attribute value is not a UINT16", name)
	}
	return v, nil
}

// readUint32Attribute reads a single UINT32 attribute of this cluster.
func readUint32Attribute(sess session.SecureSession, endpointID im.EndpointID, attributeID im.AttributeID, name string) (uint32, error) {
	resp, err := im.ReadAttribute(sess, endpointID, ClusterID, attributeID)
	if err != nil {
		return 0, fmt.Errorf("basicinformation: %s: %w", name, err)
	}
	if resp.Status != nil {
		return 0, fmt.Errorf("basicinformation: %s failed: IM status 0x%02X, cluster status 0x%02X",
			name, resp.Status.IMStatus, resp.Status.ClusterStatus)
	}
	if resp.Value == nil {
		return 0, fmt.Errorf("basicinformation: %s: ReadResponse missing attribute value", name)
	}
	v, ok := resp.Value.Unsigned4()
	if !ok {
		return 0, fmt.Errorf("basicinformation: %s: attribute value is not a UINT32", name)
	}
	return v, nil
}
