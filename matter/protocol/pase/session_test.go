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

import "testing"

func TestSessionKeysReturnsCopies(t *testing.T) {
	i2rKey := []byte{0x01, 0x02, 0x03}
	r2iKey := []byte{0x04, 0x05, 0x06}
	attestationChallenge := []byte{0x07, 0x08, 0x09}

	keys := newSessionKeys(i2rKey, r2iKey, attestationChallenge, 0, 0)

	i2rKey[0] = 0xff
	r2iKey[0] = 0xff
	attestationChallenge[0] = 0xff

	gotI2RKey := keys.I2RKey()
	if gotI2RKey[0] != 0x01 {
		t.Fatalf("I2RKey() returned aliased constructor input: got 0x%02x", gotI2RKey[0])
	}
	gotI2RKey[0] = 0xff
	if got := keys.I2RKey()[0]; got != 0x01 {
		t.Fatalf("I2RKey() returned aliased internal state: got 0x%02x", got)
	}

	gotR2IKey := keys.R2IKey()
	if gotR2IKey[0] != 0x04 {
		t.Fatalf("R2IKey() returned aliased constructor input: got 0x%02x", gotR2IKey[0])
	}
	gotR2IKey[0] = 0xff
	if got := keys.R2IKey()[0]; got != 0x04 {
		t.Fatalf("R2IKey() returned aliased internal state: got 0x%02x", got)
	}

	gotAttestationChallenge := keys.AttestationChallenge()
	if gotAttestationChallenge[0] != 0x07 {
		t.Fatalf("AttestationChallenge() returned aliased constructor input: got 0x%02x", gotAttestationChallenge[0])
	}
	gotAttestationChallenge[0] = 0xff
	if got := keys.AttestationChallenge()[0]; got != 0x07 {
		t.Fatalf("AttestationChallenge() returned aliased internal state: got 0x%02x", got)
	}
}

// TestSessionKeysNodeIDsAreAlwaysUndefined guards against a regression where
// LocalNodeID returned the ephemeral, random source node ID used only for
// addressing during the unencrypted PBKDFParamRequest/Response exchange.
// PASE sessions have no operational node identity on either side, so both
// LocalNodeID and PeerNodeID must always be 0 (matching connectedhomeip's
// SessionManager::InjectPaseSessionWithTestKey, which hardcodes
// localNodeId = kUndefinedNodeId for PASE) — this is the node ID
// secureSession.Transmit/Receive feed into the CCM nonce (4.7.2), and using
// the ephemeral PBKDF-phase ID there made every post-PASE encrypted message
// fail AES-CCM authentication against a real device.
func TestSessionKeysNodeIDsAreAlwaysUndefined(t *testing.T) {
	keys := newSessionKeys([]byte{0x01}, []byte{0x02}, []byte{0x03}, 0x1234, 0x5678)
	if got := keys.LocalNodeID(); got != 0 {
		t.Errorf("LocalNodeID() = %v, want 0", got)
	}
	if got := keys.PeerNodeID(); got != 0 {
		t.Errorf("PeerNodeID() = %v, want 0", got)
	}
}
