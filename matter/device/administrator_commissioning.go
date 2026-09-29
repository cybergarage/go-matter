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
	"time"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	"github.com/cybergarage/go-matter/matter/protocol/im"
	"github.com/cybergarage/go-matter/matter/protocol/pase"
)

// Administrator Commissioning cluster (Matter Core 11.19).
const (
	AdministratorCommissioningClusterID im.ClusterID = 0x003C

	openCommissioningWindowCommandID      im.CommandID = 0x00
	openBasicCommissioningWindowCommandID im.CommandID = 0x01
	revokeCommissioningCommandID          im.CommandID = 0x02

	windowStatusAttributeID     im.AttributeID = 0x0000
	adminFabricIndexAttributeID im.AttributeID = 0x0001
	adminVendorIDAttributeID    im.AttributeID = 0x0002

	administratorCommissioningClusterRevision = 1
	// administratorCommissioningBasic is the Basic feature, which
	// OpenBasicCommissioningWindow needs (11.19.4).
	administratorCommissioningBasic uint32 = 0x1
)

// The cluster-specific status codes (11.19.6.1).
const (
	adminCommissioningStatusBusy               uint8 = 2
	adminCommissioningStatusPAKEParameterError uint8 = 3
	adminCommissioningStatusWindowNotOpen      uint8 = 4
)

// administratorCommissioning is the server of the Administrator
// Commissioning cluster, by which an administrator opens the commissioning
// window of a commissioned device to add another fabric.
type administratorCommissioning struct {
	device *Device
}

// register adds the cluster to srv on the root endpoint. Its commands need
// Administer, and a timed invoke (11.19.8).
func (ac *administratorCommissioning) register(srv *im.Server) {
	administer := im.WithPrivilege(im.PrivilegeAdminister)
	srv.HandleCommand(rootEndpoint, AdministratorCommissioningClusterID, openCommissioningWindowCommandID, ac.openCommissioningWindow, administer)
	srv.HandleCommand(rootEndpoint, AdministratorCommissioningClusterID, openBasicCommissioningWindowCommandID, ac.openBasicCommissioningWindow, administer)
	srv.HandleCommand(rootEndpoint, AdministratorCommissioningClusterID, revokeCommissioningCommandID, ac.revokeCommissioning, administer)

	srv.HandleAttribute(rootEndpoint, AdministratorCommissioningClusterID, windowStatusAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		enc.PutUnsigned1(tag, uint8(ac.device.windowState().status))
		return im.StatusSuccess
	})
	srv.HandleAttribute(rootEndpoint, AdministratorCommissioningClusterID, adminFabricIndexAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		if state := ac.device.windowState(); state.adminFabric != 0 {
			enc.PutUnsigned1(tag, state.adminFabric)
		} else {
			enc.PutNull(tag)
		}
		return im.StatusSuccess
	})
	srv.HandleAttribute(rootEndpoint, AdministratorCommissioningClusterID, adminVendorIDAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		if state := ac.device.windowState(); state.adminFabric != 0 {
			enc.PutUnsigned2(tag, state.adminVendor)
		} else {
			enc.PutNull(tag)
		}
		return im.StatusSuccess
	})
	srv.HandleAttribute(rootEndpoint, AdministratorCommissioningClusterID, featureMapAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		enc.PutUnsigned4(tag, administratorCommissioningBasic)
		return im.StatusSuccess
	})
	srv.HandleAttribute(rootEndpoint, AdministratorCommissioningClusterID, clusterRevisionAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		enc.PutUnsigned2(tag, administratorCommissioningClusterRevision)
		return im.StatusSuccess
	})
}

// admin returns the fabric and the vendor of the administrator a request
// comes from.
func (ac *administratorCommissioning) admin(req *im.CommandRequest) (uint8, uint16) {
	fabric := ac.device.lookupSession(req.Session).fabricIndex
	if fabric == 0 {
		return 0, 0
	}
	rec, ok, err := ac.device.store.LoadDeviceFabric(fabric)
	if err != nil || !ok {
		return fabric, 0
	}
	return fabric, rec.VendorID
}

// commissioningTimeout reads the CommissioningTimeout field.
func commissioningTimeout(req *im.CommandRequest) (time.Duration, bool) {
	field, ok := req.Field(0)
	if !ok {
		return 0, false
	}
	seconds, ok := field.Unsigned()
	if !ok {
		return 0, false
	}
	return time.Duration(seconds) * time.Second, true
}

// busy reports whether a window cannot be opened now: one is open, or a
// fail-safe is armed (11.19.8.1).
func (ac *administratorCommissioning) busy() bool {
	return ac.device.IsCommissioningWindowOpen() || ac.device.failSafe.isArmed()
}

// openResult answers an opening attempt.
func openResult(err error) im.CommandResult {
	switch {
	case err == nil:
		return im.CommandStatus(im.StatusSuccess)
	case errors.Is(err, ErrCommissioningWindowOpen):
		return im.CommandClusterStatus(im.StatusFailure, adminCommissioningStatusBusy)
	default:
		log.Warnf("device: open the commissioning window: %v", err)
		return im.CommandStatus(im.StatusFailure)
	}
}

// openCommissioningWindow handles OpenCommissioningWindow (11.19.8.1),
// which opens an enhanced window with the administrator's verifier.
func (ac *administratorCommissioning) openCommissioningWindow(req *im.CommandRequest) im.CommandResult {
	if !req.Timed {
		return im.CommandStatus(im.StatusNeedsTimedInteraction)
	}
	timeout, ok1 := commissioningTimeout(req)
	verifierField, ok2 := req.Field(1)
	discriminatorField, ok3 := req.Field(2)
	iterationsField, ok4 := req.Field(3)
	saltField, ok5 := req.Field(4)
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 {
		return im.CommandStatus(im.StatusInvalidCommand)
	}
	serialized, ok1 := verifierField.Bytes()
	discriminator, ok2 := discriminatorField.Unsigned()
	iterations, ok3 := iterationsField.Unsigned()
	salt, ok4 := saltField.Bytes()
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return im.CommandStatus(im.StatusInvalidCommand)
	}
	if timeout < MinCommissioningTimeout || MaxCommissioningTimeout < timeout || MaxDiscriminator < discriminator {
		return im.CommandStatus(im.StatusInvalidCommand)
	}
	if ac.busy() {
		return im.CommandClusterStatus(im.StatusFailure, adminCommissioningStatusBusy)
	}
	verifier, err := pase.ParseVerifier(serialized, salt, int(iterations))
	if err != nil {
		log.Warnf("device: OpenCommissioningWindow: %v", err)
		return im.CommandClusterStatus(im.StatusFailure, adminCommissioningStatusPAKEParameterError)
	}
	fabric, vendor := ac.admin(req)
	return openResult(ac.device.openEnhancedWindow(timeout, verifier, uint16(discriminator), fabric, vendor))
}

// openBasicCommissioningWindow handles OpenBasicCommissioningWindow
// (11.19.8.2), which opens a window with the device's own passcode.
func (ac *administratorCommissioning) openBasicCommissioningWindow(req *im.CommandRequest) im.CommandResult {
	if !req.Timed {
		return im.CommandStatus(im.StatusNeedsTimedInteraction)
	}
	timeout, ok := commissioningTimeout(req)
	if !ok || timeout < MinCommissioningTimeout || MaxCommissioningTimeout < timeout {
		return im.CommandStatus(im.StatusInvalidCommand)
	}
	if ac.busy() {
		return im.CommandClusterStatus(im.StatusFailure, adminCommissioningStatusBusy)
	}
	fabric, vendor := ac.admin(req)
	return openResult(ac.device.openBasicWindow(timeout, fabric, vendor))
}

// revokeCommissioning handles RevokeCommissioning (11.19.8.3): it closes
// the window and expires the fail-safe, rolling back a commissioning in
// progress.
func (ac *administratorCommissioning) revokeCommissioning(req *im.CommandRequest) im.CommandResult {
	if !req.Timed {
		return im.CommandStatus(im.StatusNeedsTimedInteraction)
	}
	if !ac.device.IsCommissioningWindowOpen() {
		return im.CommandClusterStatus(im.StatusFailure, adminCommissioningStatusWindowNotOpen)
	}
	ac.device.revokeCommissioning()
	return im.CommandStatus(im.StatusSuccess)
}
