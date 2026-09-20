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

// Package descriptor provides a client for the Matter Descriptor cluster (0x001D).
// Reference: Matter Core Spec 1.5, Section 9.5.
package descriptor

import (
	"fmt"

	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	"github.com/cybergarage/go-matter/matter/protocol/im"
	"github.com/cybergarage/go-matter/matter/protocol/session"
)

// ClusterID is the Descriptor cluster identifier.
// 9.5. Descriptor Cluster.
const ClusterID im.ClusterID = 0x001D

// Attribute IDs for the Descriptor cluster.
// 9.5.5. Attributes.
const (
	// DeviceTypeListAttributeID lists the device types this endpoint implements.
	DeviceTypeListAttributeID im.AttributeID = 0x0000
	// ServerListAttributeID lists the server clusters this endpoint implements.
	ServerListAttributeID im.AttributeID = 0x0001
	// ClientListAttributeID lists the client clusters this endpoint implements.
	ClientListAttributeID im.AttributeID = 0x0002
	// PartsListAttributeID lists the endpoints composed into this endpoint.
	PartsListAttributeID im.AttributeID = 0x0003
)

// DeviceType is one entry of DeviceTypeList.
// 9.5.5.1. DeviceTypeStruct Type.
type DeviceType struct {
	// DeviceType is the device type identifier.
	DeviceType uint32
	// Revision is the implemented revision of the device type definition.
	Revision uint16
}

// DeviceTypeList reads the DeviceTypeList attribute of the given endpoint.
// 9.5.5.1. DeviceTypeStruct Type.
func DeviceTypeList(sess session.SecureSession, endpointID im.EndpointID) ([]DeviceType, error) {
	var list []DeviceType
	status, err := im.ReadListAttribute(sess, endpointID, ClusterID, DeviceTypeListAttributeID, func(dec tlv.Decoder, item tlv.Element) error {
		if !item.Type().IsStructure() {
			return fmt.Errorf("descriptor: DeviceTypeList item is not a Structure")
		}
		var dt DeviceType
		for dec.Next() {
			elem := dec.Element()
			if elem.Type().IsEndOfContainer() {
				break
			}
			ct, ok := elem.Tag().(tlv.ContextTag)
			if !ok {
				continue
			}
			switch ct.ContextNumber() {
			case 0: // DeviceType
				if v, ok := elem.Unsigned4(); ok {
					dt.DeviceType = v
				}
			case 1: // Revision
				if v, ok := elem.Unsigned2(); ok {
					dt.Revision = v
				}
			}
		}
		if err := dec.Error(); err != nil {
			return err
		}
		list = append(list, dt)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("descriptor: DeviceTypeList: %w", err)
	}
	if status != nil {
		return nil, fmt.Errorf("descriptor: DeviceTypeList failed: IM status 0x%02X, cluster status 0x%02X",
			status.IMStatus, status.ClusterStatus)
	}
	return list, nil
}

// ServerList reads the ServerList attribute of the given endpoint.
func ServerList(sess session.SecureSession, endpointID im.EndpointID) ([]im.ClusterID, error) {
	var list []im.ClusterID
	status, err := im.ReadListAttribute(sess, endpointID, ClusterID, ServerListAttributeID, func(dec tlv.Decoder, item tlv.Element) error {
		v, ok := item.Unsigned4()
		if !ok {
			return fmt.Errorf("descriptor: ServerList item is not a UINT32")
		}
		list = append(list, im.ClusterID(v))
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("descriptor: ServerList: %w", err)
	}
	if status != nil {
		return nil, fmt.Errorf("descriptor: ServerList failed: IM status 0x%02X, cluster status 0x%02X",
			status.IMStatus, status.ClusterStatus)
	}
	return list, nil
}

// ClientList reads the ClientList attribute of the given endpoint.
func ClientList(sess session.SecureSession, endpointID im.EndpointID) ([]im.ClusterID, error) {
	var list []im.ClusterID
	status, err := im.ReadListAttribute(sess, endpointID, ClusterID, ClientListAttributeID, func(dec tlv.Decoder, item tlv.Element) error {
		v, ok := item.Unsigned4()
		if !ok {
			return fmt.Errorf("descriptor: ClientList item is not a UINT32")
		}
		list = append(list, im.ClusterID(v))
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("descriptor: ClientList: %w", err)
	}
	if status != nil {
		return nil, fmt.Errorf("descriptor: ClientList failed: IM status 0x%02X, cluster status 0x%02X",
			status.IMStatus, status.ClusterStatus)
	}
	return list, nil
}

// PartsList reads the PartsList attribute of the given endpoint.
func PartsList(sess session.SecureSession, endpointID im.EndpointID) ([]im.EndpointID, error) {
	var list []im.EndpointID
	status, err := im.ReadListAttribute(sess, endpointID, ClusterID, PartsListAttributeID, func(dec tlv.Decoder, item tlv.Element) error {
		v, ok := item.Unsigned2()
		if !ok {
			return fmt.Errorf("descriptor: PartsList item is not a UINT16")
		}
		list = append(list, im.EndpointID(v))
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("descriptor: PartsList: %w", err)
	}
	if status != nil {
		return nil, fmt.Errorf("descriptor: PartsList failed: IM status 0x%02X, cluster status 0x%02X",
			status.IMStatus, status.ClusterStatus)
	}
	return list, nil
}
