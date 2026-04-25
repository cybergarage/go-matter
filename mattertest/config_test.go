// Copyright (C) 2024 The go-matter Authors. All rights reserved.
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

package mattertest

import "testing"

func TestNewAdministratorConfig(t *testing.T) {
	cfg, err := NewAdministratorConfig()
	if err != nil {
		t.Fatalf("NewAdministratorConfig() error = %v", err)
	}

	nodeID, ok := cfg.NodeID()
	if !ok || nodeID != testAdministratorNodeID {
		t.Fatalf("cfg.NodeID() = 0x%016X, %v; want 0x%016X, true", nodeID, ok, testAdministratorNodeID)
	}
	fabricID, ok := cfg.FabricID()
	if !ok || fabricID != testAdministratorFabricID {
		t.Fatalf("cfg.FabricID() = 0x%016X, %v; want 0x%016X, true", fabricID, ok, testAdministratorFabricID)
	}

	if cert, ok := cfg.RootCertificate(); !ok || len(cert) == 0 {
		t.Fatal("cfg.RootCertificate() is empty")
	}
	if noc, ok := cfg.NOC(); !ok || len(noc) == 0 {
		t.Fatal("cfg.NOC() is empty")
	}
	if key, ok := cfg.PrivateKey(); !ok || len(key) == 0 {
		t.Fatal("cfg.PrivateKey() is empty")
	}
}
