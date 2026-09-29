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

package im

import (
	"testing"

	"github.com/cybergarage/go-matter/matter/encoding/tlv"
)

func TestPrivilegeGrants(t *testing.T) {
	all := []Privilege{PrivilegeView, PrivilegeProxyView, PrivilegeOperate, PrivilegeManage, PrivilegeAdminister}
	want := map[Privilege][]Privilege{
		PrivilegeView:       {PrivilegeView},
		PrivilegeProxyView:  {PrivilegeView, PrivilegeProxyView},
		PrivilegeOperate:    {PrivilegeView, PrivilegeOperate},
		PrivilegeManage:     {PrivilegeView, PrivilegeOperate, PrivilegeManage},
		PrivilegeAdminister: all,
	}
	for _, held := range all {
		granted := map[Privilege]bool{}
		for _, p := range want[held] {
			granted[p] = true
		}
		for _, required := range all {
			if got := held.Grants(required); got != granted[required] {
				t.Errorf("%d.Grants(%d) = %v, want %v", held, required, got, granted[required])
			}
		}
	}
}

// TestServerAccessControl checks that the server asks its AccessChecker
// with the privilege each handler requires, and refuses what it denies.
func TestServerAccessControl(t *testing.T) {
	srv := testServer()
	srv.HandleCommand(0, 0x003E, 0x06, func(*CommandRequest) CommandResult {
		return CommandStatus(StatusSuccess)
	}, WithPrivilege(PrivilegeAdminister))
	var gotSession SecureSession
	var gotFiltered bool
	srv.HandleAttributeRead(0, 0x003E, 0x0005, func(req *AttributeRequest, enc tlv.Encoder, tag tlv.Tag) Status {
		gotSession = req.Session
		gotFiltered = req.FabricFiltered
		enc.PutUnsigned1(tag, 1)
		return StatusSuccess
	})
	srv.HandleAttribute(0, 0x003E, 0x0000, func(enc tlv.Encoder, tag tlv.Tag) Status {
		enc.PutUnsigned1(tag, 0)
		return StatusSuccess
	}, WithPrivilege(PrivilegeAdminister))
	// The subject holds Operate.
	srv.SetAccessChecker(func(req AccessRequest) bool {
		return PrivilegeOperate.Grants(req.Privilege)
	})
	client := startServer(t, srv)

	resp, err := Invoke(client, 0, 0x0030, 0x00, armFailSafeFields(60))
	if err != nil || !resp.IsSuccess() {
		t.Fatalf("a command needing Operate: (%+v, %v)", resp, err)
	}
	resp, err = Invoke(client, 0, 0x003E, 0x06, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status.IMStatus != uint8(StatusUnsupportedAccess) {
		t.Fatalf("a command needing Administer: status %+v, want UnsupportedAccess", resp.Status)
	}

	// A concrete read reports the refusal; a wildcard one leaves the
	// attribute out.
	read, err := ReadAttribute(client, 0, 0x003E, 0x0000)
	if err != nil {
		t.Fatal(err)
	}
	if read.Status == nil || read.Status.IMStatus != uint8(StatusUnsupportedAccess) {
		t.Fatalf("a read needing Administer: %+v, want UnsupportedAccess", read.Status)
	}
	got := reportedPaths(t, readRaw(t, client, [3]int64{0, 0x003E, -1}))
	if len(got) != 1 || got[0] != [3]uint64{0, 0x003E, 0x0005} {
		t.Fatalf("wildcard read reported %v, want only the attribute the subject may read", got)
	}

	// A reader which needs the request gets the session and the filter.
	if gotSession == nil || !gotFiltered {
		t.Fatalf("the reader got session %v, fabric-filtered %v", gotSession, gotFiltered)
	}
}
