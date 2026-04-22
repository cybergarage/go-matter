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

package config

import "testing"

func TestNewOperationalCredentialConfigDefaults(t *testing.T) {
	cfg := NewOperationalCredentialConfig()

	if got, ok := cfg.RootCertificate(); got != nil || ok {
		t.Fatalf("RootCertificate() = (%v, %v), want (nil, false)", got, ok)
	}
	if got, ok := cfg.NOC(); got != nil || ok {
		t.Fatalf("NOC() = (%v, %v), want (nil, false)", got, ok)
	}
	if got, ok := cfg.ICAC(); got != nil || ok {
		t.Fatalf("ICAC() = (%v, %v), want (nil, false)", got, ok)
	}
	if got, ok := cfg.IPK(); got != nil || ok {
		t.Fatalf("IPK() = (%v, %v), want (nil, false)", got, ok)
	}
	if got, ok := cfg.CASEAdminNodeID(); got != 0 || ok {
		t.Fatalf("CASEAdminNodeID() = (%v, %v), want (0, false)", got, ok)
	}
	if got, ok := cfg.AdminVendorID(); got != 0 || ok {
		t.Fatalf("AdminVendorID() = (%v, %v), want (0, false)", got, ok)
	}
	if got := cfg.Map(); len(got) != 0 {
		t.Fatalf("Map() = %#v, want empty map", got)
	}
}

func TestNewOperationalCredentialConfigWithOptions(t *testing.T) {
	rootCert := []byte{0x01, 0x02}
	noc := []byte{0x03, 0x04}
	icac := []byte{0x05}
	ipk := []byte{0x06, 0x07}
	caseAdminNodeID := uint64(0x1122334455667788)
	adminVendorID := uint16(0x1234)

	cfg := NewOperationalCredentialConfig(
		WithRootCertificate(rootCert),
		WithNOC(noc),
		WithICAC(icac),
		WithIPK(ipk),
		WithCASEAdminNodeID(caseAdminNodeID),
		WithAdminVendorID(adminVendorID),
	)

	if got, ok := cfg.RootCertificate(); !ok || string(got) != string(rootCert) {
		t.Fatalf("RootCertificate() = (%v, %v), want (%v, true)", got, ok, rootCert)
	}
	if got, ok := cfg.NOC(); !ok || string(got) != string(noc) {
		t.Fatalf("NOC() = (%v, %v), want (%v, true)", got, ok, noc)
	}
	if got, ok := cfg.ICAC(); !ok || string(got) != string(icac) {
		t.Fatalf("ICAC() = (%v, %v), want (%v, true)", got, ok, icac)
	}
	if got, ok := cfg.IPK(); !ok || string(got) != string(ipk) {
		t.Fatalf("IPK() = (%v, %v), want (%v, true)", got, ok, ipk)
	}
	if got, ok := cfg.CASEAdminNodeID(); !ok || got != caseAdminNodeID {
		t.Fatalf("CASEAdminNodeID() = (%v, %v), want (%v, true)", got, ok, caseAdminNodeID)
	}
	if got, ok := cfg.AdminVendorID(); !ok || got != adminVendorID {
		t.Fatalf("AdminVendorID() = (%v, %v), want (%v, true)", got, ok, adminVendorID)
	}

	gotMap := cfg.Map()
	if got, ok := gotMap["rootCertificate"].([]byte); !ok || string(got) != string(rootCert) {
		t.Fatalf("Map()[rootCertificate] = %#v, want %v", gotMap["rootCertificate"], rootCert)
	}
	if got, ok := gotMap["noc"].([]byte); !ok || string(got) != string(noc) {
		t.Fatalf("Map()[noc] = %#v, want %v", gotMap["noc"], noc)
	}
	if got, ok := gotMap["icac"].([]byte); !ok || string(got) != string(icac) {
		t.Fatalf("Map()[icac] = %#v, want %v", gotMap["icac"], icac)
	}
	if got, ok := gotMap["ipk"].([]byte); !ok || string(got) != string(ipk) {
		t.Fatalf("Map()[ipk] = %#v, want %v", gotMap["ipk"], ipk)
	}
	if got, ok := gotMap["caseAdminNodeID"].(uint64); !ok || got != caseAdminNodeID {
		t.Fatalf("Map()[caseAdminNodeID] = %#v, want %v", gotMap["caseAdminNodeID"], caseAdminNodeID)
	}
	if got, ok := gotMap["adminVendorID"].(uint16); !ok || got != adminVendorID {
		t.Fatalf("Map()[adminVendorID] = %#v, want %v", gotMap["adminVendorID"], adminVendorID)
	}
}
