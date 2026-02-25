// Copyright (C) 2025 The go-matter Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package spake2p

import (
	"math/big"
	"testing"
)

func TestSPAKE2pKeyGeneration(t *testing.T) {
	spake := New()
	if err := spake.GenerateKey(); err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	x, y := spake.Public()
	if x == nil || y == nil {
		t.Error("Public key is nil")
	}
}

func TestSPAKE2pTranscript(t *testing.T) {
	spake := New()
	data1 := []byte("hello")
	data2 := []byte("world")
	spake.AppendTranscript(data1)
	spake.AppendTranscript(data2)
	trans := spake.Transcript()
	if string(trans) != "helloworld" {
		t.Errorf("Transcript mismatch: got %s", string(trans))
	}
}

func TestSPAKE2pSetPoints(t *testing.T) {
	spake := New()
	mx, my := big.NewInt(1), big.NewInt(2)
	nx, ny := big.NewInt(3), big.NewInt(4)
	sx, sy := big.NewInt(5), big.NewInt(6)
	spake.SetM(mx, my)
	spake.SetN(nx, ny)
	spake.SetS(sx, sy)
	// No assertion, just ensure no panic and values are set
}

func TestSPAKE2pComputeSharedError(t *testing.T) {
	spake := New()
	_, err := spake.ComputeShared(big.NewInt(1), big.NewInt(2))
	if err == nil {
		t.Error("Expected error when private key is not set")
	}
}
