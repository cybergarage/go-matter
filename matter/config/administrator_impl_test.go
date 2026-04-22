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

func TestNewAdministratorConfigDefaults(t *testing.T) {
	cfg := NewAdministratorConfig()

	if got, ok := cfg.NodeID(); got != 0 || ok {
		t.Fatalf("NodeID() = (%v, %v), want (0, false)", got, ok)
	}
	if got, ok := cfg.FabricID(); got != 0 || ok {
		t.Fatalf("FabricID() = (%v, %v), want (0, false)", got, ok)
	}
	if got, ok := cfg.RootCertificate(); got != nil || ok {
		t.Fatalf("RootCertificate() = (%v, %v), want (nil, false)", got, ok)
	}
	if got, ok := cfg.NOC(); got != nil || ok {
		t.Fatalf("NOC() = (%v, %v), want (nil, false)", got, ok)
	}
	if got, ok := cfg.ICAC(); got != nil || ok {
		t.Fatalf("ICAC() = (%v, %v), want (nil, false)", got, ok)
	}
	if got, ok := cfg.PrivateKey(); got != nil || ok {
		t.Fatalf("PrivateKey() = (%v, %v), want (nil, false)", got, ok)
	}
	if got := cfg.Map(); len(got) != 0 {
		t.Fatalf("Map() = %#v, want empty map", got)
	}
}

func TestNewAdministratorConfigWithOptions(t *testing.T) {
	rootCert := []byte{0x01, 0x02}
	noc := []byte{0x03}
	icac := []byte{0x04}
	privateKey := []byte{0x05, 0x06}
	nodeID := uint64(0x1122334455667788)
	fabricID := uint64(0x8877665544332211)

	cfg := NewAdministratorConfig(
		WithAdministratorNodeID(nodeID),
		WithAdministratorFabricID(fabricID),
		WithAdministratorRootCertificate(rootCert),
		WithAdministratorNOC(noc),
		WithAdministratorICAC(icac),
		WithAdministratorPrivateKey(privateKey),
	)

	if got, ok := cfg.NodeID(); !ok || got != nodeID {
		t.Fatalf("NodeID() = (%v, %v), want (%v, true)", got, ok, nodeID)
	}
	if got, ok := cfg.FabricID(); !ok || got != fabricID {
		t.Fatalf("FabricID() = (%v, %v), want (%v, true)", got, ok, fabricID)
	}
	if got, ok := cfg.RootCertificate(); !ok || string(got) != string(rootCert) {
		t.Fatalf("RootCertificate() = (%v, %v), want (%v, true)", got, ok, rootCert)
	}
	if got, ok := cfg.NOC(); !ok || string(got) != string(noc) {
		t.Fatalf("NOC() = (%v, %v), want (%v, true)", got, ok, noc)
	}
	if got, ok := cfg.ICAC(); !ok || string(got) != string(icac) {
		t.Fatalf("ICAC() = (%v, %v), want (%v, true)", got, ok, icac)
	}
	if got, ok := cfg.PrivateKey(); !ok || string(got) != string(privateKey) {
		t.Fatalf("PrivateKey() = (%v, %v), want (%v, true)", got, ok, privateKey)
	}
}
