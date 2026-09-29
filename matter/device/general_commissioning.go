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
	"time"

	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	"github.com/cybergarage/go-matter/matter/protocol/im"
)

// General Commissioning cluster (Matter Core 11.10).
const (
	GeneralCommissioningClusterID im.ClusterID = 0x0030

	armFailSafeCommandID                   im.CommandID = 0x00
	armFailSafeResponseCommandID           im.CommandID = 0x01
	setRegulatoryConfigCommandID           im.CommandID = 0x02
	setRegulatoryConfigResponseCommandID   im.CommandID = 0x03
	commissioningCompleteCommandID         im.CommandID = 0x04
	commissioningCompleteResponseCommandID im.CommandID = 0x05

	breadcrumbAttributeID                   im.AttributeID = 0x0000
	basicCommissioningInfoAttributeID       im.AttributeID = 0x0001
	regulatoryConfigAttributeID             im.AttributeID = 0x0002
	locationCapabilityAttributeID           im.AttributeID = 0x0003
	supportsConcurrentConnectionAttributeID im.AttributeID = 0x0004

	featureMapAttributeID      im.AttributeID = 0xFFFC
	clusterRevisionAttributeID im.AttributeID = 0xFFFD

	generalCommissioningClusterRevision = 1
)

// RegulatoryLocation is the RegulatoryLocationTypeEnum (11.10.4.2).
type RegulatoryLocation uint8

const (
	RegulatoryIndoor        RegulatoryLocation = 0
	RegulatoryOutdoor       RegulatoryLocation = 1
	RegulatoryIndoorOutdoor RegulatoryLocation = 2
)

// rootEndpoint is the endpoint of the utility clusters (Matter Core 9.2).
const rootEndpoint im.EndpointID = 0

// generalCommissioning is the server of the General Commissioning cluster.
type generalCommissioning struct {
	mutex    sync.Mutex
	failSafe *failSafe
	lookup   sessionLookup
	// onComplete is called when CommissioningComplete succeeds.
	onComplete         func()
	breadcrumb         uint64
	regulatoryConfig   RegulatoryLocation
	countryCode        string
	locationCapability RegulatoryLocation
}

func newGeneralCommissioning(fs *failSafe, lookup sessionLookup) *generalCommissioning {
	gc := &generalCommissioning{
		mutex:              sync.Mutex{},
		failSafe:           fs,
		lookup:             lookup,
		onComplete:         nil,
		breadcrumb:         0,
		regulatoryConfig:   RegulatoryIndoorOutdoor,
		countryCode:        "XX",
		locationCapability: RegulatoryIndoorOutdoor,
	}
	// The breadcrumb resets when the fail-safe expires (11.10.5.1).
	previous := fs.onExpire
	fs.onExpire = func() {
		gc.setBreadcrumb(0)
		if previous != nil {
			previous()
		}
	}
	return gc
}

func (gc *generalCommissioning) setBreadcrumb(v uint64) {
	gc.mutex.Lock()
	defer gc.mutex.Unlock()
	gc.breadcrumb = v
}

// register adds the cluster to srv on the root endpoint. Its commands need
// Administer (11.10.7).
func (gc *generalCommissioning) register(srv *im.Server) {
	administer := im.WithPrivilege(im.PrivilegeAdminister)
	srv.HandleCommand(rootEndpoint, GeneralCommissioningClusterID, armFailSafeCommandID, gc.armFailSafe, administer)
	srv.HandleCommand(rootEndpoint, GeneralCommissioningClusterID, setRegulatoryConfigCommandID, gc.setRegulatoryConfig, administer)
	srv.HandleCommand(rootEndpoint, GeneralCommissioningClusterID, commissioningCompleteCommandID, gc.commissioningComplete, administer)

	srv.HandleAttribute(rootEndpoint, GeneralCommissioningClusterID, breadcrumbAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		gc.mutex.Lock()
		defer gc.mutex.Unlock()
		if err := enc.PutUnsigned(tag, gc.breadcrumb); err != nil {
			return im.StatusFailure
		}
		return im.StatusSuccess
	})
	srv.HandleAttribute(rootEndpoint, GeneralCommissioningClusterID, basicCommissioningInfoAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		enc.BeginStructure(tag)
		enc.PutUnsigned2(tlv.NewContextTag(0), uint16(DefaultFailSafeExpiryLength/time.Second))
		enc.PutUnsigned2(tlv.NewContextTag(1), uint16(gc.failSafe.maxCumulative/time.Second))
		if err := enc.EndContainer(); err != nil {
			return im.StatusFailure
		}
		return im.StatusSuccess
	})
	srv.HandleAttribute(rootEndpoint, GeneralCommissioningClusterID, regulatoryConfigAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		gc.mutex.Lock()
		defer gc.mutex.Unlock()
		enc.PutUnsigned1(tag, uint8(gc.regulatoryConfig))
		return im.StatusSuccess
	})
	srv.HandleAttribute(rootEndpoint, GeneralCommissioningClusterID, locationCapabilityAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		enc.PutUnsigned1(tag, uint8(gc.locationCapability))
		return im.StatusSuccess
	})
	srv.HandleAttribute(rootEndpoint, GeneralCommissioningClusterID, supportsConcurrentConnectionAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		// Commissioning over IP keeps the same network connection.
		enc.PutBool(tag, true)
		return im.StatusSuccess
	})
	srv.HandleAttribute(rootEndpoint, GeneralCommissioningClusterID, featureMapAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		enc.PutUnsigned4(tag, 0)
		return im.StatusSuccess
	})
	srv.HandleAttribute(rootEndpoint, GeneralCommissioningClusterID, clusterRevisionAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		enc.PutUnsigned2(tag, generalCommissioningClusterRevision)
		return im.StatusSuccess
	})
}

// commissioningResponse encodes the {ErrorCode, DebugText} fields every
// General Commissioning response command carries.
func commissioningResponse(cmd im.CommandID, code CommissioningError) im.CommandResult {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewContextTag(1))
	enc.PutUnsigned1(tlv.NewContextTag(0), uint8(code))
	if err := enc.PutUTF81(tlv.NewContextTag(1), ""); err != nil {
		return im.CommandStatus(im.StatusFailure)
	}
	if err := enc.EndContainer(); err != nil {
		return im.CommandStatus(im.StatusFailure)
	}
	return im.CommandResponse(cmd, enc.Bytes())
}

// armFailSafe handles ArmFailSafe (11.10.7.2).
func (gc *generalCommissioning) armFailSafe(req *im.CommandRequest) im.CommandResult {
	expiryField, ok := req.Field(0)
	if !ok {
		return im.CommandStatus(im.StatusInvalidCommand)
	}
	expiry, ok := expiryField.Unsigned()
	if !ok || 0xFFFF < expiry {
		return im.CommandStatus(im.StatusInvalidCommand)
	}
	breadcrumbField, ok := req.Field(1)
	if !ok {
		return im.CommandStatus(im.StatusInvalidCommand)
	}
	breadcrumb, ok := breadcrumbField.Unsigned()
	if !ok {
		return im.CommandStatus(im.StatusInvalidCommand)
	}

	code := gc.failSafe.arm(gc.lookup(req.Session).fabricIndex, time.Duration(expiry)*time.Second)
	if code == CommissioningOK {
		gc.setBreadcrumb(breadcrumb)
		if expiry == 0 {
			gc.setBreadcrumb(0)
		}
	}
	return commissioningResponse(armFailSafeResponseCommandID, code)
}

// setRegulatoryConfig handles SetRegulatoryConfig (11.10.7.4).
func (gc *generalCommissioning) setRegulatoryConfig(req *im.CommandRequest) im.CommandResult {
	locationField, ok1 := req.Field(0)
	countryField, ok2 := req.Field(1)
	breadcrumbField, ok3 := req.Field(2)
	if !ok1 || !ok2 || !ok3 {
		return im.CommandStatus(im.StatusInvalidCommand)
	}
	location, ok1 := locationField.Unsigned()
	country, ok2 := countryField.UTF8()
	breadcrumb, ok3 := breadcrumbField.Unsigned()
	if !ok1 || !ok2 || !ok3 {
		return im.CommandStatus(im.StatusInvalidCommand)
	}
	if uint64(RegulatoryIndoorOutdoor) < location || len(country) != 2 {
		return im.CommandStatus(im.StatusConstraintError)
	}

	gc.mutex.Lock()
	defer gc.mutex.Unlock()
	// A device which only operates indoors or outdoors refuses the other
	// (11.10.7.4).
	if gc.locationCapability != RegulatoryIndoorOutdoor && RegulatoryLocation(location) != gc.locationCapability {
		return commissioningResponse(setRegulatoryConfigResponseCommandID, CommissioningValueOutsideRange)
	}
	gc.regulatoryConfig = RegulatoryLocation(location)
	gc.countryCode = country
	gc.breadcrumb = breadcrumb
	return commissioningResponse(setRegulatoryConfigResponseCommandID, CommissioningOK)
}

// commissioningComplete handles CommissioningComplete (11.10.7.6): only
// over CASE, on the fabric the fail-safe was armed for, while it is armed.
func (gc *generalCommissioning) commissioningComplete(req *im.CommandRequest) im.CommandResult {
	info := gc.lookup(req.Session)
	if !info.isCASE {
		return commissioningResponse(commissioningCompleteResponseCommandID, CommissioningInvalidAuthentication)
	}
	code, err := gc.failSafe.commit(info.fabricIndex)
	if err != nil {
		return im.CommandStatus(im.StatusFailure)
	}
	if code == CommissioningOK {
		gc.setBreadcrumb(0)
		if gc.onComplete != nil {
			gc.onComplete()
		}
	}
	return commissioningResponse(commissioningCompleteResponseCommandID, code)
}
