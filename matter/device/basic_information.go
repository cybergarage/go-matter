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
	"sync"

	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	"github.com/cybergarage/go-matter/matter/protocol/im"
)

// Basic Information cluster (Matter Core 11.1).
const (
	BasicInformationClusterID im.ClusterID = 0x0028

	dataModelRevisionAttributeID     im.AttributeID = 0x0000
	vendorNameAttributeID            im.AttributeID = 0x0001
	vendorIDAttributeID              im.AttributeID = 0x0002
	productNameAttributeID           im.AttributeID = 0x0003
	productIDAttributeID             im.AttributeID = 0x0004
	nodeLabelAttributeID             im.AttributeID = 0x0005
	hardwareVersionAttributeID       im.AttributeID = 0x0007
	hardwareVersionStringAttributeID im.AttributeID = 0x0008
	softwareVersionAttributeID       im.AttributeID = 0x0009
	softwareVersionStringAttributeID im.AttributeID = 0x000A
	uniqueIDAttributeID              im.AttributeID = 0x0012
	capabilityMinimaAttributeID      im.AttributeID = 0x0013

	basicInformationFeatureMapAttributeID      im.AttributeID = 0xFFFC
	basicInformationClusterRevisionAttributeID im.AttributeID = 0xFFFD

	// maxNodeLabelLength is the longest NodeLabel (11.1.6.6).
	maxNodeLabelLength = 32

	// dataModelRevision is the Data Model revision this device implements
	// (11.1.6.1), Matter Core Specification Version 1.5.
	dataModelRevision             = 25
	basicInformationClusterRev    = 3
	defaultCaseSessionsPerFabric  = 3
	defaultSubscriptionsPerFabric = 3
)

// basicInformation is the server of the Basic Information cluster: it
// reports the fixed identity a commissioner reads during commissioning
// (11.1. Basic Information Cluster), sourced from the device's
// CommissionableService.
type basicInformation struct {
	mutex           sync.Mutex
	nodeLabel       string
	vendorID        uint16
	productID       uint16
	deviceName      string
	hardwareVersion uint16
	softwareVersion uint32
	uniqueID        string
}

func newBasicInformation(vendorID, productID uint16, deviceName, uniqueID string) *basicInformation {
	return &basicInformation{
		mutex:           sync.Mutex{},
		nodeLabel:       "",
		vendorID:        vendorID,
		productID:       productID,
		deviceName:      deviceName,
		hardwareVersion: 0,
		softwareVersion: 0,
		uniqueID:        uniqueID,
	}
}

// register adds the cluster to srv on the root endpoint.
func (bi *basicInformation) register(srv *im.Server) {
	srv.HandleAttribute(rootEndpoint, BasicInformationClusterID, dataModelRevisionAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		enc.PutUnsigned2(tag, dataModelRevision)
		return im.StatusSuccess
	})
	srv.HandleAttribute(rootEndpoint, BasicInformationClusterID, vendorNameAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		if err := enc.PutUTF81(tag, "go-matter"); err != nil {
			return im.StatusFailure
		}
		return im.StatusSuccess
	})
	srv.HandleAttribute(rootEndpoint, BasicInformationClusterID, vendorIDAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		enc.PutUnsigned2(tag, bi.vendorID)
		return im.StatusSuccess
	})
	srv.HandleAttribute(rootEndpoint, BasicInformationClusterID, productNameAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		name := bi.deviceName
		if name == "" {
			name = "go-matter device"
		}
		if err := enc.PutUTF81(tag, name); err != nil {
			return im.StatusFailure
		}
		return im.StatusSuccess
	})
	srv.HandleAttribute(rootEndpoint, BasicInformationClusterID, productIDAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		enc.PutUnsigned2(tag, bi.productID)
		return im.StatusSuccess
	})
	// NodeLabel is the name a user gives the node; writing it needs Manage
	// (11.1.6.6).
	srv.HandleAttribute(rootEndpoint, BasicInformationClusterID, nodeLabelAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		bi.mutex.Lock()
		defer bi.mutex.Unlock()
		if err := enc.PutUTF8(tag, bi.nodeLabel); err != nil {
			return im.StatusFailure
		}
		return im.StatusSuccess
	})
	srv.HandleAttributeWrite(rootEndpoint, BasicInformationClusterID, nodeLabelAttributeID, func(req *im.AttributeWriteRequest) im.Status {
		_, elem, err := req.Decoder()
		if err != nil {
			return im.StatusInvalidDataType
		}
		label, ok := elem.UTF8()
		if !ok {
			return im.StatusInvalidDataType
		}
		if maxNodeLabelLength < len(label) {
			return im.StatusConstraintError
		}
		bi.mutex.Lock()
		defer bi.mutex.Unlock()
		bi.nodeLabel = label
		return im.StatusSuccess
	}, im.WithPrivilege(im.PrivilegeManage))
	srv.HandleAttribute(rootEndpoint, BasicInformationClusterID, hardwareVersionAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		enc.PutUnsigned2(tag, bi.hardwareVersion)
		return im.StatusSuccess
	})
	srv.HandleAttribute(rootEndpoint, BasicInformationClusterID, hardwareVersionStringAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		if err := enc.PutUTF81(tag, "0"); err != nil {
			return im.StatusFailure
		}
		return im.StatusSuccess
	})
	srv.HandleAttribute(rootEndpoint, BasicInformationClusterID, softwareVersionAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		enc.PutUnsigned4(tag, bi.softwareVersion)
		return im.StatusSuccess
	})
	srv.HandleAttribute(rootEndpoint, BasicInformationClusterID, softwareVersionStringAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		if err := enc.PutUTF81(tag, "0"); err != nil {
			return im.StatusFailure
		}
		return im.StatusSuccess
	})
	srv.HandleAttribute(rootEndpoint, BasicInformationClusterID, uniqueIDAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		if err := enc.PutUTF81(tag, bi.uniqueID); err != nil {
			return im.StatusFailure
		}
		return im.StatusSuccess
	})
	srv.HandleAttribute(rootEndpoint, BasicInformationClusterID, capabilityMinimaAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		enc.BeginStructure(tag)
		enc.PutUnsigned2(tlv.NewContextTag(0), defaultCaseSessionsPerFabric)
		enc.PutUnsigned2(tlv.NewContextTag(1), defaultSubscriptionsPerFabric)
		if err := enc.EndContainer(); err != nil {
			return im.StatusFailure
		}
		return im.StatusSuccess
	})
	srv.HandleAttribute(rootEndpoint, BasicInformationClusterID, basicInformationFeatureMapAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		enc.PutUnsigned4(tag, 0)
		return im.StatusSuccess
	})
	srv.HandleAttribute(rootEndpoint, BasicInformationClusterID, basicInformationClusterRevisionAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		enc.PutUnsigned2(tag, basicInformationClusterRev)
		return im.StatusSuccess
	})
}
