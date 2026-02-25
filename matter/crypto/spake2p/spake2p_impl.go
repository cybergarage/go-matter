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
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"math/big"
)

// spake2pImpl implements the SPAKE2p interface over P-256.
type spake2pImpl struct {
	curve   elliptic.Curve
	private *big.Int
	x, y    *big.Int // Public key

	// SPAKE2+ protocol points (RFC 9383)
	Mx, My *big.Int // M = w0*P + M
	Nx, Ny *big.Int // N = w1*P + N
	Sx, Sy *big.Int // S = w0*P + N (for verifier)

	// Transcript for hashing protocol messages
	transcript []byte
}

func newSPAKE2pImpl() *spake2pImpl {
	return &spake2pImpl{
		curve:      elliptic.P256(),
		private:    nil,
		x:          nil,
		y:          nil,
		Mx:         nil,
		My:         nil,
		Nx:         nil,
		Ny:         nil,
		Sx:         nil,
		Sy:         nil,
		transcript: nil,
	}
}

func (s *spake2pImpl) GenerateKey() error {
	priv, x, y, err := elliptic.GenerateKey(s.curve, rand.Reader)
	if err != nil {
		return err
	}
	s.private = new(big.Int).SetBytes(priv)
	s.x = x
	s.y = y
	return nil
}

func (s *spake2pImpl) Public() (*big.Int, *big.Int) {
	return s.x, s.y
}

func (s *spake2pImpl) SetM(mx, my *big.Int) {
	s.Mx = mx
	s.My = my
}

func (s *spake2pImpl) SetN(nx, ny *big.Int) {
	s.Nx = nx
	s.Ny = ny
}

func (s *spake2pImpl) SetS(sx, sy *big.Int) {
	s.Sx = sx
	s.Sy = sy
}

func (s *spake2pImpl) AppendTranscript(data []byte) {
	s.transcript = append(s.transcript, data...)
}

func (s *spake2pImpl) Transcript() []byte {
	return s.transcript
}

func (s *spake2pImpl) ComputeShared(peerX, peerY *big.Int) ([]byte, error) {
	if s.private == nil {
		return nil, errors.New("private key not set")
	}
	x, _ := s.curve.ScalarMult(peerX, peerY, s.private.Bytes())
	return x.Bytes(), nil
}
