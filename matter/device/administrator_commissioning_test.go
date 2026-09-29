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
	"testing"

	"github.com/cybergarage/go-matter/matter/cluster/generalcommissioning"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	"github.com/cybergarage/go-matter/matter/mdns"
	"github.com/cybergarage/go-matter/matter/protocol/im"
	"github.com/cybergarage/go-matter/matter/protocol/pase"
	"github.com/cybergarage/go-matter/matter/protocol/session"
	"github.com/cybergarage/go-matter/matter/types"
)

// commissionedDevice commissions a device to the end and returns it with
// an administrator's CASE session.
func commissionedDevice(t *testing.T) (*Device, *recordingAdvertiser, *testCA, *udpClient, session.SecureSession) {
	t.Helper()
	d, adv, paseSession, client := startCommissioningWithAdvertiser(t)
	ca := newTestCA(t, testFabricID)
	addNOCOverPASE(t, paseSession, ca, testCommissioneeNode)
	operational := caseSession(t, client, ca.admin(t, testAdminNodeID), testCommissioneeNode)
	if err := generalcommissioning.CommissioningComplete(operational, 0); err != nil {
		t.Fatal(err)
	}
	return d, adv, ca, client, operational
}

func timeoutFields(t *testing.T, seconds uint16) []byte {
	t.Helper()
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewContextTag(1))
	enc.PutUnsigned2(tlv.NewContextTag(0), seconds)
	if err := enc.EndContainer(); err != nil {
		t.Fatal(err)
	}
	return enc.Bytes()
}

func enhancedWindowFields(t *testing.T, seconds uint16, verifier []byte, discriminator uint16, iterations uint32, salt []byte) []byte {
	t.Helper()
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewContextTag(1))
	enc.PutUnsigned2(tlv.NewContextTag(0), seconds)
	if err := enc.PutOctet(tlv.NewContextTag(1), verifier); err != nil {
		t.Fatal(err)
	}
	enc.PutUnsigned2(tlv.NewContextTag(2), discriminator)
	enc.PutUnsigned4(tlv.NewContextTag(3), iterations)
	if err := enc.PutOctet(tlv.NewContextTag(4), salt); err != nil {
		t.Fatal(err)
	}
	if err := enc.EndContainer(); err != nil {
		t.Fatal(err)
	}
	return enc.Bytes()
}

func invokeAdmin(t *testing.T, sess session.SecureSession, cmd im.CommandID, fields []byte) im.InvokeStatus {
	t.Helper()
	resp, err := im.TimedInvoke(sess, 0, AdministratorCommissioningClusterID, cmd, fields, 0)
	if err != nil {
		t.Fatal(err)
	}
	return resp.Status
}

func readAdminAttribute(t *testing.T, sess session.SecureSession, attr im.AttributeID) (uint64, bool) {
	t.Helper()
	resp, err := im.ReadAttribute(sess, 0, AdministratorCommissioningClusterID, attr)
	if err != nil || resp.Status != nil {
		t.Fatalf("read attribute 0x%04X: (%+v, %v)", attr, resp, err)
	}
	return resp.Value.Unsigned()
}

// TestAdministratorCommissioningBasicWindow opens and revokes a basic
// commissioning window as an administrator of a commissioned device.
func TestAdministratorCommissioningBasicWindow(t *testing.T) {
	d, adv, ca, client, admin := commissionedDevice(t)
	if d.IsCommissioningWindowOpen() || adv.isCommissionable() {
		t.Fatal("the window is open after commissioning")
	}

	// The commands need a timed interaction.
	resp, err := im.Invoke(admin, 0, AdministratorCommissioningClusterID, openBasicCommissioningWindowCommandID, timeoutFields(t, 180))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status.IMStatus != uint8(im.StatusNeedsTimedInteraction) {
		t.Fatalf("an untimed OpenBasicCommissioningWindow: %+v, want NeedsTimedInteraction", resp.Status)
	}
	if status := invokeAdmin(t, admin, openBasicCommissioningWindowCommandID, timeoutFields(t, 60)); status.IMStatus != uint8(im.StatusInvalidCommand) {
		t.Fatalf("a 60-second window: %+v, want InvalidCommand", status)
	}

	if status := invokeAdmin(t, admin, openBasicCommissioningWindowCommandID, timeoutFields(t, 180)); status.IMStatus != 0 {
		t.Fatalf("OpenBasicCommissioningWindow: %+v", status)
	}
	if !d.IsCommissioningWindowOpen() || !adv.isCommissionable() {
		t.Fatal("the basic window did not open")
	}
	if v, _ := readAdminAttribute(t, admin, windowStatusAttributeID); WindowStatus(v) != BasicWindowOpen {
		t.Fatalf("WindowStatus = %d, want BasicWindowOpen", v)
	}
	if v, ok := readAdminAttribute(t, admin, adminFabricIndexAttributeID); !ok || v != 1 {
		t.Fatalf("AdminFabricIndex = (%d, %v), want 1", v, ok)
	}
	if v, ok := readAdminAttribute(t, admin, adminVendorIDAttributeID); !ok || v != uint64(testAdminVendorID) {
		t.Fatalf("AdminVendorId = (%d, %v), want 0x%X", v, ok, testAdminVendorID)
	}
	if status := invokeAdmin(t, admin, openBasicCommissioningWindowCommandID, timeoutFields(t, 180)); status.ClusterStatus != adminCommissioningStatusBusy {
		t.Fatalf("a second opening: %+v, want Busy", status)
	}

	// Another node of the fabric may not open windows.
	stranger := caseSession(t, client, ca.admin(t, testAdminNodeID+1), testCommissioneeNode)
	resp, err = im.TimedInvoke(stranger, 0, AdministratorCommissioningClusterID, revokeCommissioningCommandID, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status.IMStatus != uint8(im.StatusUnsupportedAccess) {
		t.Fatalf("RevokeCommissioning by a node the ACL does not name: %+v, want UnsupportedAccess", resp.Status)
	}

	if status := invokeAdmin(t, admin, revokeCommissioningCommandID, nil); status.IMStatus != 0 {
		t.Fatalf("RevokeCommissioning: %+v", status)
	}
	if d.IsCommissioningWindowOpen() || adv.isCommissionable() {
		t.Fatal("RevokeCommissioning left the window open")
	}
	if status := invokeAdmin(t, admin, revokeCommissioningCommandID, nil); status.ClusterStatus != adminCommissioningStatusWindowNotOpen {
		t.Fatalf("RevokeCommissioning without a window: %+v, want WindowNotOpen", status)
	}
}

// TestAdministratorCommissioningEnhancedWindow opens an enhanced window
// with a verifier and a discriminator the administrator chose, which PASE
// then authenticates with instead of the device's own.
func TestAdministratorCommissioningEnhancedWindow(t *testing.T) {
	d, adv, _, _, admin := commissionedDevice(t)
	const onetime = types.Passcode(34567890)
	const discriminator = 0x0123
	verifier, err := pase.NewRandomSaltVerifier(onetime, 1000)
	if err != nil {
		t.Fatal(err)
	}

	short := verifier.Bytes()[:96]
	if status := invokeAdmin(t, admin, openCommissioningWindowCommandID, enhancedWindowFields(t, 180, short, discriminator, 1000, verifier.Salt)); status.ClusterStatus != adminCommissioningStatusPAKEParameterError {
		t.Fatalf("a short verifier: %+v, want PAKEParameterError", status)
	}
	if status := invokeAdmin(t, admin, openCommissioningWindowCommandID, enhancedWindowFields(t, 180, verifier.Bytes(), discriminator, 1000, verifier.Salt)); status.IMStatus != 0 {
		t.Fatalf("OpenCommissioningWindow: %+v", status)
	}
	if v, _ := readAdminAttribute(t, admin, windowStatusAttributeID); WindowStatus(v) != EnhancedWindowOpen {
		t.Fatalf("WindowStatus = %d, want EnhancedWindowOpen", v)
	}
	svc := d.CommissionableService()
	if svc.Discriminator != discriminator || svc.CommissioningMode != mdns.CommissioningModeDynamicPasscode {
		t.Fatalf("advertised discriminator 0x%X mode %v, want 0x%X with CM=2", svc.Discriminator, svc.CommissioningMode, discriminator)
	}
	if !adv.isCommissionable() {
		t.Fatal("the enhanced window is not advertised")
	}

	// PASE authenticates with the one-time passcode, not the device's.
	if err := tryPASE(t, d, testPasscode); err == nil {
		t.Fatal("PASE with the device's passcode succeeded in an enhanced window")
	}
	// The device ends the failed exchange just after the initiator gives
	// up; a new one starts once it has.
	waitFor(t, "the failed PASE exchange to end", func() bool {
		d.mu.Lock()
		defer d.mu.Unlock()
		return d.pase == nil
	})
	if err := tryPASE(t, d, onetime); err != nil {
		t.Fatalf("PASE with the one-time passcode: %v", err)
	}

	// Revoking ends the commissioning and restores the device's own
	// discriminator.
	if status := invokeAdmin(t, admin, revokeCommissioningCommandID, nil); status.IMStatus != 0 {
		t.Fatalf("RevokeCommissioning: %+v", status)
	}
	if d.commissionerSession() != nil || d.failSafe.isArmed() {
		t.Fatal("RevokeCommissioning left the commissioning in progress")
	}
	if got := d.CommissionableService().Discriminator; got != 3840 {
		t.Fatalf("discriminator after the window = %d, want the device's 3840", got)
	}
}
