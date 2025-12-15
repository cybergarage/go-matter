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

package pase

import (
	"github.com/cybergarage/go-matter/matter/crypto/pake/spake2p"
	"github.com/cybergarage/go-matter/matter/crypto/pbkdf"
)

// HandshakeRole represents the role in the PASE handshake.
type HandshakeRole int

const (
	// HandshakeRoleClient represents the client/initiator role (prover in SPAKE2+).
	HandshakeRoleClient HandshakeRole = iota
	// HandshakeRoleServer represents the server/responder role (verifier in SPAKE2+).
	HandshakeRoleServer
)

// HandshakeOptions contains options for creating a PASE handshake.
type HandshakeOptions struct {
	// Passcode is the setup passcode (typically 6-8 digits).
	Passcode []byte
	// Salt is the PBKDF salt.
	Salt []byte
	// PBKDFIter is the number of PBKDF2 iterations (typically 1000-15000 per Matter spec).
	PBKDFIter int
	// Role indicates client or server role.
	Role HandshakeRole
}

// Handshake represents a PASE handshake session.
type Handshake struct {
	role  HandshakeRole
	suite *spake2p.Suite
}

// NewHandshake creates a new PASE handshake with the given options.
// It derives w0 and w1 from the passcode using PBKDF2 and initializes the SPAKE2+ suite.
func NewHandshake(opts HandshakeOptions) (*Handshake, error) {
	// Derive w0 and w1 from passcode using PBKDF2.
	// Matter spec requires a 64-byte output split into two 32-byte halves.
	pbkdfParams := pbkdf.Params{
		Password: opts.Passcode,
		Salt:     opts.Salt,
		Iter:     opts.PBKDFIter,
		KeyLen:   64,  // 64 bytes total: w0 (32 bytes) + w1 (32 bytes)
		Hash:     nil, // Uses default SHA-256
	}
	derived := pbkdf.CryptoPBKDF(pbkdfParams)

	// Split the 64-byte output into w0 and w1.
	w0 := derived[:32]
	w1 := derived[32:]

	// Map HandshakeRole to spake2p.Role.
	spakeRole := spake2p.RoleProver
	if opts.Role == HandshakeRoleServer {
		spakeRole = spake2p.RoleVerifier
	}

	// Create SPAKE2+ suite.
	suite := spake2p.New(spake2p.Params{
		W0:   w0,
		W1:   w1,
		Role: spakeRole,
		Hash: nil, // Uses default SHA-256
	})

	return &Handshake{
		role:  opts.Role,
		suite: suite,
	}, nil
}

// Start initiates the handshake and returns the local public share.
// For client role, this returns X (Pake1 message).
// For server role, this returns Y (part of Pake2 message).
func (h *Handshake) Start() ([]byte, error) {
	return h.suite.Start()
}

// ProcessPeer processes the peer's public share.
// For client role, this processes Y from Pake2.
// For server role, this processes X from Pake1.
func (h *Handshake) ProcessPeer(peerShare []byte) error {
	return h.suite.ProcessPeer(peerShare)
}

// VerifyConfirmation verifies the peer's confirmation MAC.
// For client role, this verifies the verifier's confirmation from Pake2.
// For server role, this verifies the prover's confirmation from Pake3.
func (h *Handshake) VerifyConfirmation(peerMAC []byte) error {
	return h.suite.VerifyConfirmation(peerMAC)
}

// GenerateConfirmation generates the local confirmation MAC.
// For client role, this generates the prover's confirmation for Pake3.
// For server role, this generates the verifier's confirmation for Pake2.
func (h *Handshake) GenerateConfirmation() ([]byte, error) {
	return h.suite.GenerateConfirmation()
}

// ExportKeys derives and exports the session keys.
// Should be called after successful confirmation exchange.
func (h *Handshake) ExportKeys() ([]byte, error) {
	return h.suite.ExportKeys()
}
