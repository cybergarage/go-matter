// Copyright (C) 2025 The go-matter Authors. All rights reserved.
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

package spake2p

import (
	"testing"
)

// TestSuiteCreation verifies that a SPAKE2+ suite can be created.
func TestSuiteCreation(t *testing.T) {
	params := Params{
		W0:   make([]byte, 32),
		W1:   make([]byte, 32),
		Role: RoleProver,
		Hash: nil, // Uses default
	}

	suite := New(params)
	if suite == nil {
		t.Fatal("New() returned nil suite")
	}
}

// TestSuiteMethodsReturnErrors verifies that unimplemented methods return errors.
// TODO: Replace with actual test vectors once cryptographic implementation is complete.
func TestSuiteMethodsReturnErrors(t *testing.T) {
	params := Params{
		W0:   make([]byte, 32),
		W1:   make([]byte, 32),
		Role: RoleProver,
	}

	suite := New(params)

	// All methods should return errors until implemented
	_, err := suite.Start()
	if err == nil {
		t.Error("Start() should return error (not implemented)")
	}

	err = suite.ProcessPeer(make([]byte, 65))
	if err == nil {
		t.Error("ProcessPeer() should return error (not implemented)")
	}

	err = suite.VerifyConfirmation(make([]byte, 32))
	if err == nil {
		t.Error("VerifyConfirmation() should return error (not implemented)")
	}

	_, err = suite.ExportKeys()
	if err == nil {
		t.Error("ExportKeys() should return error (not implemented)")
	}

	_, err = suite.GenerateConfirmation()
	if err == nil {
		t.Error("GenerateConfirmation() should return error (not implemented)")
	}
}

// TestConstants verifies that the M and N point constants have correct format.
func TestConstants(t *testing.T) {
	// Both should be 65 bytes (SEC1 uncompressed point format)
	if len(PointM) != 65 {
		t.Errorf("PointM length = %d, want 65", len(PointM))
	}
	if len(PointN) != 65 {
		t.Errorf("PointN length = %d, want 65", len(PointN))
	}

	// Both should start with 0x04 (uncompressed point indicator)
	if PointM[0] != 0x04 {
		t.Errorf("PointM[0] = %x, want 0x04", PointM[0])
	}
	if PointN[0] != 0x04 {
		t.Errorf("PointN[0] = %x, want 0x04", PointN[0])
	}
}
