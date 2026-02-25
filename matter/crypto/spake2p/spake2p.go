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

// References:
//   - RFC 9383: https://datatracker.ietf.org/doc/html/rfc9383
//   - https://github.com/project-chip/connectedhomeip

import (
	"math/big"
)

// SPAKE2p defines the interface for SPAKE2+ protocol operations.
type SPAKE2p interface {
	GenerateKey() error
	Public() (*big.Int, *big.Int)
	SetM(mx, my *big.Int)
	SetN(nx, ny *big.Int)
	SetS(sx, sy *big.Int)
	AppendTranscript(data []byte)
	Transcript() []byte
	ComputeShared(peerX, peerY *big.Int) ([]byte, error)
}

// New creates a new SPAKE2p instance using P-256.
func New() SPAKE2p {
	return newSPAKE2pImpl()
}
