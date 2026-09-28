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
	"time"

	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	"github.com/cybergarage/go-matter/matter/protocol/im"
)

func commandFields(t *testing.T, build func(enc tlv.Encoder)) map[uint8]tlv.Element {
	t.Helper()
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	build(enc)
	if err := enc.EndContainer(); err != nil {
		t.Fatal(err)
	}
	dec := tlv.NewDecoderWithBytes(enc.Bytes())
	fields := map[uint8]tlv.Element{}
	dec.Next()
	for dec.Next() {
		elem := dec.Element()
		if ct, ok := elem.Tag().(tlv.ContextTag); ok {
			fields[uint8(ct.ContextNumber())] = elem
		}
	}
	return fields
}

func errorCode(t *testing.T, result im.CommandResult) CommissioningError {
	t.Helper()
	if !result.HasResponse {
		t.Fatalf("answered with status %#x instead of a response command", result.Status)
	}
	dec := tlv.NewDecoderWithBytes(result.Fields)
	dec.Next()
	dec.Next()
	v, _ := dec.Element().Unsigned()
	return CommissioningError(v)
}

func armRequest(t *testing.T, expiry uint16, breadcrumb uint64) *im.CommandRequest {
	t.Helper()
	return &im.CommandRequest{Fields: commandFields(t, func(enc tlv.Encoder) {
		enc.PutUnsigned2(tlv.NewContextTag(0), expiry)
		_ = enc.PutUnsigned(tlv.NewContextTag(1), breadcrumb)
	})}
}

func TestGeneralCommissioningCommands(t *testing.T) {
	fs, ft, _ := newTestFailSafe(t)
	current := sessionInfo{isCASE: false, fabricIndex: 0}
	gc := newGeneralCommissioning(fs, func(im.SecureSession) sessionInfo { return current })

	if code := errorCode(t, gc.armFailSafe(armRequest(t, 60, 7))); code != CommissioningOK {
		t.Fatalf("ArmFailSafe ErrorCode = %d", code)
	}
	if gc.breadcrumb != 7 {
		t.Fatalf("Breadcrumb = %d, want 7", gc.breadcrumb)
	}

	reg := &im.CommandRequest{Fields: commandFields(t, func(enc tlv.Encoder) {
		enc.PutUnsigned1(tlv.NewContextTag(0), uint8(RegulatoryOutdoor))
		_ = enc.PutUTF81(tlv.NewContextTag(1), "JP")
		_ = enc.PutUnsigned(tlv.NewContextTag(2), 8)
	})}
	if code := errorCode(t, gc.setRegulatoryConfig(reg)); code != CommissioningOK {
		t.Fatalf("SetRegulatoryConfig ErrorCode = %d", code)
	}
	if gc.regulatoryConfig != RegulatoryOutdoor || gc.countryCode != "JP" || gc.breadcrumb != 8 {
		t.Fatalf("after SetRegulatoryConfig: %d %q %d", gc.regulatoryConfig, gc.countryCode, gc.breadcrumb)
	}
	badCountry := &im.CommandRequest{Fields: commandFields(t, func(enc tlv.Encoder) {
		enc.PutUnsigned1(tlv.NewContextTag(0), 0)
		_ = enc.PutUTF81(tlv.NewContextTag(1), "JPN")
		_ = enc.PutUnsigned(tlv.NewContextTag(2), 0)
	})}
	if r := gc.setRegulatoryConfig(badCountry); r.HasResponse || r.Status != im.StatusConstraintError {
		t.Fatalf("a 3-letter country code: %+v, want ConstraintError", r)
	}

	if code := errorCode(t, gc.commissioningComplete(&im.CommandRequest{})); code != CommissioningInvalidAuthentication {
		t.Fatalf("CommissioningComplete over PASE: ErrorCode %d, want InvalidAuthentication", code)
	}
	// AddNOC gives the fail-safe to the new fabric; only a CASE session on
	// that fabric completes it.
	fs.addFabric(1)
	current = sessionInfo{isCASE: true, fabricIndex: 2}
	if code := errorCode(t, gc.commissioningComplete(&im.CommandRequest{})); code != CommissioningInvalidAuthentication {
		t.Fatalf("CommissioningComplete over CASE on another fabric: ErrorCode %d, want InvalidAuthentication", code)
	}
	current = sessionInfo{isCASE: true, fabricIndex: 1}
	if code := errorCode(t, gc.commissioningComplete(&im.CommandRequest{})); code != CommissioningOK {
		t.Fatalf("CommissioningComplete over CASE: ErrorCode %d", code)
	}
	if fs.isArmed() || gc.breadcrumb != 0 {
		t.Fatalf("after CommissioningComplete: armed %v, breadcrumb %d", fs.isArmed(), gc.breadcrumb)
	}
	if code := errorCode(t, gc.commissioningComplete(&im.CommandRequest{})); code != CommissioningNoFailSafe {
		t.Fatalf("CommissioningComplete without a fail-safe: ErrorCode %d, want NoFailSafe", code)
	}

	// An expiry resets the breadcrumb.
	current = sessionInfo{isCASE: false, fabricIndex: 0}
	gc.armFailSafe(armRequest(t, 10, 9))
	ft.advance(10 * time.Second)
	if gc.breadcrumb != 0 {
		t.Fatalf("Breadcrumb after the fail-safe expired = %d, want 0", gc.breadcrumb)
	}

	if r := gc.armFailSafe(&im.CommandRequest{Fields: map[uint8]tlv.Element{}}); r.HasResponse || r.Status != im.StatusInvalidCommand {
		t.Fatalf("ArmFailSafe without fields: %+v, want InvalidCommand", r)
	}
}
