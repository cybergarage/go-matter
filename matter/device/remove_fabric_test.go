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
	"context"
	"testing"
	"time"

	"github.com/cybergarage/go-matter/matter/cluster/generalcommissioning"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	"github.com/cybergarage/go-matter/matter/protocol/im"
	"github.com/cybergarage/go-matter/matter/protocol/pase"
	"github.com/cybergarage/go-matter/matter/protocol/session"
)

func invokeNOC(t *testing.T, sess session.SecureSession, cmd im.CommandID, build func(enc tlv.Encoder)) (NOCStatus, uint64) {
	t.Helper()
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewContextTag(1))
	build(enc)
	if err := enc.EndContainer(); err != nil {
		t.Fatal(err)
	}
	resp, err := im.Invoke(sess, 0, OperationalCredentialsClusterID, cmd, enc.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !resp.IsSuccess() {
		t.Fatalf("command 0x%02X: status %+v, want a NOCResponse", cmd, resp.Status)
	}
	code, ok := resp.Field(0)
	if !ok {
		t.Fatalf("command 0x%02X: the NOCResponse lacks StatusCode", cmd)
	}
	status, _ := code.Unsigned()
	var index uint64
	if field, ok := resp.Field(1); ok {
		index, _ = field.Unsigned()
	}
	return NOCStatus(status), index
}

func updateLabel(t *testing.T, sess session.SecureSession, label string) (NOCStatus, uint64) {
	t.Helper()
	return invokeNOC(t, sess, updateFabricLabelCommandID, func(enc tlv.Encoder) {
		_ = enc.PutUTF8(tlv.NewContextTag(0), label)
	})
}

func removeFabric(t *testing.T, sess session.SecureSession, index uint8) (NOCStatus, uint64) {
	t.Helper()
	return invokeNOC(t, sess, removeFabricCommandID, func(enc tlv.Encoder) {
		enc.PutUnsigned1(tlv.NewContextTag(0), index)
	})
}

func (d *Device) casesOn(fabricIndex uint8) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for _, s := range d.sessions {
		if s.isCASE && s.fabricIndex == fabricIndex {
			n++
		}
	}
	return n
}

// TestRemoveFabricAndUpdateLabel commissions the device onto two fabrics,
// labels them, and removes them: the other fabric's first, then the
// administrator's own, which leaves the device on no fabric and
// commissionable again.
func TestRemoveFabricAndUpdateLabel(t *testing.T) {
	d, adv, _, _, first := commissionedDevice(t)

	// A second fabric, through a window the application opens.
	if err := d.OpenCommissioningWindow(MinCommissioningTimeout); err != nil {
		t.Fatal(err)
	}
	client2 := dialDevice(t, d)
	pase2 := paseSession(t, client2)
	ca2 := newTestCA(t, testFabricID+1)
	addNOCOverPASE(t, pase2, ca2, testCommissioneeNode+1)
	second := caseSession(t, client2, ca2.admin(t, testAdminNodeID), testCommissioneeNode+1)
	if err := generalcommissioning.CommissioningComplete(second, 0); err != nil {
		t.Fatal(err)
	}
	waitOperational(t, adv, 2)

	// Labels are per fabric, and unique.
	if status, index := updateLabel(t, first, "Home"); status != NOCStatusOK || index != 1 {
		t.Fatalf("UpdateFabricLabel(Home) = (%d, %d), want OK on fabric 1", status, index)
	}
	if status, _ := updateLabel(t, second, "Home"); status != NOCStatusLabelConflict {
		t.Fatalf("UpdateFabricLabel(Home) on another fabric = %d, want LabelConflict", status)
	}
	if status, index := updateLabel(t, second, "Office"); status != NOCStatusOK || index != 2 {
		t.Fatalf("UpdateFabricLabel(Office) = (%d, %d), want OK on fabric 2", status, index)
	}
	fabrics, err := d.store.ListDeviceFabrics()
	if err != nil || len(fabrics) != 2 || fabrics[0].Label != "Home" || fabrics[1].Label != "Office" {
		t.Fatalf("fabrics after labelling: (%+v, %v)", fabrics, err)
	}

	// Removing the second fabric ends its sessions and its advertisement.
	if status, _ := removeFabric(t, first, 9); status != NOCStatusInvalidFabricIndex {
		t.Fatalf("RemoveFabric(9) = %d, want InvalidFabricIndex", status)
	}
	if status, index := removeFabric(t, first, 2); status != NOCStatusOK || index != 2 {
		t.Fatalf("RemoveFabric(2) = (%d, %d), want OK", status, index)
	}
	waitFor(t, "the sessions on fabric 2 to close", func() bool { return d.casesOn(2) == 0 })
	waitOperational(t, adv, 1)
	if fabrics, err := d.store.ListDeviceFabrics(); err != nil || len(fabrics) != 1 || fabrics[0].FabricIndex != 1 {
		t.Fatalf("fabrics after RemoveFabric(2): (%+v, %v)", fabrics, err)
	}
	if acl, _ := d.store.LoadACL(2); len(acl) != 0 {
		t.Fatalf("the ACL of fabric 2 survived RemoveFabric: %+v", acl)
	}
	if d.IsCommissioningWindowOpen() {
		t.Fatal("the window opened although the device is still on a fabric")
	}

	// Removing the administrator's own fabric answers, then ends its
	// session; on no fabric, the device is commissionable again.
	if status, index := removeFabric(t, first, 1); status != NOCStatusOK || index != 1 {
		t.Fatalf("RemoveFabric(1) = (%d, %d), want OK", status, index)
	}
	waitFor(t, "the sessions on fabric 1 to close", func() bool { return d.casesOn(1) == 0 })
	waitOperational(t, adv, 0)
	if fabrics, err := d.store.ListDeviceFabrics(); err != nil || len(fabrics) != 0 {
		t.Fatalf("fabrics after RemoveFabric(1): (%+v, %v)", fabrics, err)
	}
	if !d.IsCommissioningWindowOpen() || !adv.isCommissionable() {
		t.Fatal("the device on no fabric did not open its commissioning window")
	}
}

// paseSession establishes PASE with the device's passcode over client.
func paseSession(t *testing.T, client *udpClient) session.SecureSession {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	keys, err := pase.NewInitiator(client, testPasscode).EstablishSession(ctx)
	if err != nil {
		t.Fatalf("PASE: %v", err)
	}
	return session.NewSecureSession(client, keys)
}
