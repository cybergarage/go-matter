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

package pase

import (
	"testing"
)

// TestHandshakeCreation verifies that a handshake can be created.
// Actual cryptographic operations are not tested as they are not yet implemented.
func TestHandshakeCreation(t *testing.T) {
	opts := HandshakeOptions{
		Passcode:  []byte("123456"),
		Salt:      []byte("test-salt"),
		PBKDFIter: 1000,
		Role:      HandshakeRoleClient,
	}

	h, err := NewHandshake(opts)
	if err != nil {
		t.Fatalf("NewHandshake failed: %v", err)
	}
	if h == nil {
		t.Fatal("NewHandshake returned nil handshake")
	}

	// Verify Start() returns expected error (not implemented yet)
	_, err = h.Start()
	if err == nil {
		t.Error("Start() should return error (not implemented)")
	}
}

// TestMessageCreation verifies that PASE messages can be created.
func TestMessageCreation(t *testing.T) {
	// Test Pake1
	pake1 := NewPake1([]byte("test-x"))
	if pake1 == nil {
		t.Fatal("NewPake1 returned nil")
	}
	bytes1 := pake1.Bytes()
	if len(bytes1) == 0 {
		t.Error("Pake1.Bytes() returned empty")
	}
	if bytes1[0] != opPASEPake1 {
		t.Errorf("Pake1 opcode = %x, want %x", bytes1[0], opPASEPake1)
	}

	// Test Pake2
	pake2 := NewPake2([]byte("test-y"), []byte("test-cmac"))
	if pake2 == nil {
		t.Fatal("NewPake2 returned nil")
	}
	bytes2 := pake2.Bytes()
	if len(bytes2) == 0 {
		t.Error("Pake2.Bytes() returned empty")
	}
	if bytes2[0] != opPASEPake2 {
		t.Errorf("Pake2 opcode = %x, want %x", bytes2[0], opPASEPake2)
	}

	// Test Pake3
	pake3 := NewPake3([]byte("test-smac"))
	if pake3 == nil {
		t.Fatal("NewPake3 returned nil")
	}
	bytes3 := pake3.Bytes()
	if len(bytes3) == 0 {
		t.Error("Pake3.Bytes() returned empty")
	}
	if bytes3[0] != opPASEPake3 {
		t.Errorf("Pake3 opcode = %x, want %x", bytes3[0], opPASEPake3)
	}
}
