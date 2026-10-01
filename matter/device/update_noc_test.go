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
	"github.com/cybergarage/go-matter/matter/cluster/operationalcredentials"
	"github.com/cybergarage/go-matter/matter/credentials"
	caseprotocol "github.com/cybergarage/go-matter/matter/protocol/case"
	"github.com/cybergarage/go-matter/matter/protocol/session"
)

// issueForUpdate asks the device for a CSR for UpdateNOC and issues a NOC
// for node under ca.
func issueForUpdate(t *testing.T, sess session.SecureSession, ca *testCA, node uint64) []byte {
	t.Helper()
	nocsr, _, err := operationalcredentials.CSRRequestForUpdateNOC(sess, 0, randomNonce(t))
	if err != nil {
		t.Fatalf("CSRRequest for UpdateNOC: %v", err)
	}
	elements, err := credentials.ParseNOCSRElements(nocsr)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := credentials.ParseCSR(elements.CSR)
	if err != nil {
		t.Fatal(err)
	}
	nocDER, err := ca.ca.IssueNOC(csr, node)
	if err != nil {
		t.Fatal(err)
	}
	return nocDER
}

// tryCASE reports whether CASE to node succeeds on a new connection.
func tryCASE(t *testing.T, d *Device, ca *testCA, node uint64) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := caseprotocol.NewInitiator(dialDevice(t, d), ca.admin(t, testAdminNodeID), caseprotocol.WithPeerNodeID(node), caseprotocol.WithIPK(testIPK)).EstablishSession(ctx)
	return err == nil
}

func TestUpdateNOC(t *testing.T) {
	d, adv, ca, _, admin := commissionedDevice(t)
	waitOperational(t, adv, 1)
	newNode := testCommissioneeNode + 0x100

	// A CSR for UpdateNOC needs the fail-safe, and UpdateNOC a CSR for
	// UpdateNOC.
	if _, _, err := operationalcredentials.CSRRequestForUpdateNOC(admin, 0, randomNonce(t)); err == nil {
		t.Fatal("CSRRequest for UpdateNOC succeeded without the fail-safe")
	}
	if err := generalcommissioning.ArmFailSafe(admin, 0, 60, 1); err != nil {
		t.Fatal(err)
	}
	nocsr, _, err := operationalcredentials.CSRRequest(admin, 0, randomNonce(t))
	if err != nil {
		t.Fatal(err)
	}
	elements, err := credentials.ParseNOCSRElements(nocsr)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := credentials.ParseCSR(elements.CSR)
	if err != nil {
		t.Fatal(err)
	}
	nocForAddNOC, err := ca.ca.IssueNOC(csr, newNode)
	if err != nil {
		t.Fatal(err)
	}
	if err := operationalcredentials.UpdateNOC(admin, 0, nocForAddNOC, nil); err == nil {
		t.Fatal("UpdateNOC after a CSRRequest for AddNOC succeeded")
	}

	// A NOC for the key of the CSR replaces the fabric's.
	noc := issueForUpdate(t, admin, ca, newNode)
	if err := operationalcredentials.UpdateNOC(admin, 0, noc, nil); err != nil {
		t.Fatalf("UpdateNOC: %v", err)
	}
	if err := operationalcredentials.UpdateNOC(admin, 0, noc, nil); err == nil {
		t.Fatal("a second UpdateNOC under the same fail-safe succeeded")
	}
	if !tryCASE(t, d, ca, newNode) {
		t.Fatal("CASE to the new node ID failed while the fail-safe is armed")
	}
	if tryCASE(t, d, ca, testCommissioneeNode) {
		t.Fatal("CASE to the old node ID succeeded after UpdateNOC")
	}

	// CommissioningComplete keeps it.
	if err := generalcommissioning.CommissioningComplete(admin, 0); err != nil {
		t.Fatalf("CommissioningComplete: %v", err)
	}
	if fabrics, err := d.store.ListDeviceFabrics(); err != nil || len(fabrics) != 1 || fabrics[0].NodeID != newNode {
		t.Fatalf("the fabrics after UpdateNOC are (%+v, %v), want node 0x%X", fabrics, err, newNode)
	}
	waitFor(t, "the new node ID to be advertised", func() bool {
		svcs := adv.lastOperational()
		return len(svcs) == 1 && svcs[0].NodeID == newNode
	})

	// An UpdateNOC the fail-safe rolls back is undone.
	if err := generalcommissioning.ArmFailSafe(admin, 0, 60, 2); err != nil {
		t.Fatal(err)
	}
	if err := operationalcredentials.UpdateNOC(admin, 0, issueForUpdate(t, admin, ca, newNode+1), nil); err != nil {
		t.Fatalf("UpdateNOC: %v", err)
	}
	if err := generalcommissioning.ArmFailSafe(admin, 0, 0, 3); err != nil {
		t.Fatal(err)
	}
	if fabrics, err := d.store.ListDeviceFabrics(); err != nil || len(fabrics) != 1 || fabrics[0].NodeID != newNode {
		t.Fatalf("the fabrics after the rollback are (%+v, %v), want node 0x%X", fabrics, err, newNode)
	}
	if !tryCASE(t, d, ca, newNode) {
		t.Fatal("CASE to the committed node ID failed after the rollback")
	}
}
