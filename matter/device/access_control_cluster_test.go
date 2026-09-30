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

	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	"github.com/cybergarage/go-matter/matter/protocol/im"
	"github.com/cybergarage/go-matter/matter/protocol/session"
	"github.com/cybergarage/go-matter/matter/store"
)

// aclEntryFields is an AccessControlEntryStruct to write: nil subjects
// and targets are written as null.
type aclEntryFields struct {
	privilege uint8
	authMode  uint8
	subjects  []uint64
	targets   []store.ACLTarget
}

func writeACL(t *testing.T, sess session.SecureSession, entries ...aclEntryFields) im.Status {
	t.Helper()
	resp, err := im.WriteAttribute(sess, 0, AccessControlClusterID, aclAttributeID, func(enc tlv.Encoder) error {
		enc.BeginArray(tlv.NewContextTag(2))
		for _, e := range entries {
			enc.BeginStructure(tlv.NewAnonymousTag())
			if err := encodeACLEntryFields(enc, store.ACLEntry{
				Privilege: store.Privilege(e.privilege),
				AuthMode:  store.AuthMode(e.authMode),
				Subjects:  e.subjects,
				Targets:   e.targets,
			}); err != nil {
				return err
			}
			if err := enc.EndContainer(); err != nil {
				return err
			}
		}
		return enc.EndContainer()
	})
	if err != nil {
		t.Fatalf("write ACL: %v", err)
	}
	return im.Status(resp.Status.IMStatus)
}

// readACL reads the ACL, returning each entry's fields by context tag.
func readACLEntries(t *testing.T, sess session.SecureSession) ([]map[uint8]tlv.Element, *im.InvokeStatus) {
	t.Helper()
	var entries []map[uint8]tlv.Element
	status, err := im.ReadListAttribute(sess, 0, AccessControlClusterID, aclAttributeID, func(dec tlv.Decoder, _ tlv.Element) error {
		fields := map[uint8]tlv.Element{}
		depth := 1
		for depth > 0 && dec.Next() {
			elem := dec.Element()
			switch {
			case elem.Type().IsEndOfContainer():
				depth--
			case depth == 1:
				if tag, ok := contextTagNumber(elem); ok {
					fields[tag] = elem
				}
				if elem.Type().IsContainer() {
					depth++
				}
			case elem.Type().IsContainer():
				depth++
			}
		}
		entries = append(entries, fields)
		return dec.Error()
	})
	if err != nil {
		t.Fatalf("read ACL: %v", err)
	}
	return entries, status
}

func TestAccessControlCluster(t *testing.T) {
	d, adv, _, _, admin := commissionedDevice(t)
	waitOperational(t, adv, 1)

	entries, status := readACLEntries(t, admin)
	if status != nil || len(entries) != 1 {
		t.Fatalf("read ACL = (%d entries, %+v), want the administrator's entry", len(entries), status)
	}
	if v, _ := entries[0][aclPrivilegeTag].Unsigned(); v != uint64(store.PrivilegeAdminister) {
		t.Fatalf("the entry has privilege %d, want Administer", v)
	}
	if v, _ := entries[0][fabricIndexTag].Unsigned(); v != 1 {
		t.Fatalf("the entry is on fabric %d, want 1", v)
	}
	for attribute, want := range map[im.AttributeID]uint64{
		subjectsPerAccessControlEntryAttributeID: subjectsPerAccessControlEntry,
		targetsPerAccessControlEntryAttributeID:  targetsPerAccessControlEntry,
		accessControlEntriesPerFabricAttributeID: accessControlEntriesPerFabric,
	} {
		resp, err := im.ReadAttribute(admin, 0, AccessControlClusterID, attribute)
		if err != nil || resp.Status != nil {
			t.Fatalf("read 0x%04X: (%+v, %v)", attribute, resp, err)
		}
		if v, _ := resp.Value.Unsigned(); v != want {
			t.Fatalf("attribute 0x%04X = %d, want %d", attribute, v, want)
		}
	}

	administer := aclEntryFields{uint8(store.PrivilegeAdminister), uint8(store.AuthModeCASE), []uint64{testAdminNodeID}, nil}
	basicInformation := uint32(BasicInformationClusterID)
	root := uint16(0)
	viewer := aclEntryFields{uint8(store.PrivilegeView), uint8(store.AuthModeCASE), []uint64{0x1234}, []store.ACLTarget{{Cluster: &basicInformation, Endpoint: &root, DeviceType: nil}}}
	if s := writeACL(t, admin, administer, viewer); s != im.StatusSuccess {
		t.Fatalf("write ACL: status %#x", uint8(s))
	}
	acl, err := d.store.LoadACL(1)
	if err != nil || len(acl) != 2 || acl[1].Subjects[0] != 0x1234 || *acl[1].Targets[0].Cluster != basicInformation {
		t.Fatalf("the stored ACL is (%+v, %v)", acl, err)
	}

	for _, tc := range []struct {
		name    string
		entries []aclEntryFields
		want    im.Status
	}{
		{"PASE entry", []aclEntryFields{administer, {uint8(store.PrivilegeView), uint8(store.AuthModePASE), nil, nil}}, im.StatusConstraintError},
		{"Group Administer", []aclEntryFields{administer, {uint8(store.PrivilegeAdminister), uint8(store.AuthModeGroup), []uint64{1}, nil}}, im.StatusConstraintError},
		{"bad CASE subject", []aclEntryFields{administer, {uint8(store.PrivilegeView), uint8(store.AuthModeCASE), []uint64{0xFFFF_FFFF_FFFF_0001}, nil}}, im.StatusConstraintError},
		{"empty target", []aclEntryFields{administer, {uint8(store.PrivilegeView), uint8(store.AuthModeCASE), nil, []store.ACLTarget{{}}}}, im.StatusConstraintError},
		{"too many entries", []aclEntryFields{administer, viewer, viewer, viewer, viewer}, im.StatusResourceExhausted},
	} {
		if s := writeACL(t, admin, tc.entries...); s != tc.want {
			t.Errorf("write ACL with %s: status %#x, want %#x", tc.name, uint8(s), uint8(tc.want))
		}
	}
	if acl, _ := d.store.LoadACL(1); len(acl) != 2 {
		t.Fatalf("a refused write changed the ACL to %+v", acl)
	}

	// An administrator who leaves itself only View can no longer read the
	// ACL, which needs Administer.
	if s := writeACL(t, admin, aclEntryFields{uint8(store.PrivilegeView), uint8(store.AuthModeCASE), []uint64{testAdminNodeID}, nil}); s != im.StatusSuccess {
		t.Fatalf("write ACL: status %#x", uint8(s))
	}
	if _, status := readACLEntries(t, admin); status == nil || status.IMStatus != uint8(im.StatusUnsupportedAccess) {
		t.Fatalf("read ACL with View = %+v, want UNSUPPORTED_ACCESS", status)
	}
	if v, err := im.ReadBoolAttribute(admin, 0, GeneralCommissioningClusterID, 0x0004); err != nil || !v {
		t.Fatalf("read with View = (%v, %v), want it allowed", v, err)
	}
}
