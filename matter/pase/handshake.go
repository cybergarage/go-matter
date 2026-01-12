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
	"crypto/sha256"
	"hash"

	"github.com/cybergarage/go-matter/matter/crypto/pake/spake2p"
	"github.com/cybergarage/go-matter/matter/crypto/pbkdf"
)

// HandshakeRole represents the role in the PASE handshake.
type HandshakeRole int

const (
	// HandshakeRoleClient represents the client role (initiator, maps to SPAKE2+ Prover).
	HandshakeRoleClient HandshakeRole = iota
	// HandshakeRoleServer represents the server role (responder, maps to SPAKE2+ Verifier).
	HandshakeRoleServer
)

// HandshakeOptions holds the options for creating a PASE handshake.
type HandshakeOptions struct {
	// Passcode is the Matter passcode used to derive w0 and w1.
	Passcode []byte
	// Salt is the salt used in PBKDF2 derivation.
	Salt []byte
	// PBKDFIter is the number of iterations for PBKDF2 (default 1000 per Matter spec).
	PBKDFIter int
	// Hash function to use (defaults to SHA-256).
	Hash func() hash.Hash
}

// Handshake represents a PASE handshake instance that wraps SPAKE2+.
type Handshake struct {
	role  HandshakeRole
	suite *spake2p.Suite
}

// NewHandshake creates a new PASE handshake with the given role and options.
// It derives w0 and w1 from the passcode using PBKDF2 and initializes the SPAKE2+ suite.
// Reference: Matter Core Spec 1.5, Section 3.9 (PBKDF), Section 4.14.1 (PASE Protocol).
func NewHandshake(role HandshakeRole, opts HandshakeOptions) *Handshake {
	// Set default hash if not provided
	if opts.Hash == nil {
		opts.Hash = sha256.New
	}

	// Set default PBKDF iterations if not provided
	if opts.PBKDFIter == 0 {
		opts.PBKDFIter = 1000 // Default per Matter Core Spec 1.5 Section 3.9
	}

	// Derive w0 and w1 using PBKDF2
	// Reference: Matter Core Spec 1.5, Section 3.9 (PBKDF), Section 4.14.1 (PASE)
	// According to Matter spec, we derive a 64-byte buffer and split it into two 32-byte halves
	w0w1 := pbkdf.CryptoPBKDF(pbkdf.Params{
		Password: opts.Passcode,
		Salt:     opts.Salt,
		Iter:     opts.PBKDFIter,
		KeyLen:   64, // 64 bytes total: 32 for w0, 32 for w1
		Hash:     opts.Hash,
	})

	// Split into w0 (first 32 bytes) and w1 (last 32 bytes)
	w0 := w0w1[:32]
	w1 := w0w1[32:64]

	// Map HandshakeRole to SPAKE2+ Role
	var spakeRole spake2p.Role
	if role == HandshakeRoleClient {
		spakeRole = spake2p.RoleProver
	} else {
		spakeRole = spake2p.RoleVerifier
	}

	// Create SPAKE2+ suite
	suite := spake2p.New(spakeRole, spake2p.Params{
		W0:   w0,
		W1:   w1,
		Hash: opts.Hash,
	})

	return &Handshake{
		role:  role,
		suite: suite,
	}
}

// Start initiates the PASE handshake and returns the public value to send to the peer.
// Reference: Matter Core Spec 1.5, Section 4.14.1 (PASE Protocol)
// For client role, this returns X (Pake1 message).
// For server role, this returns Y (part of Pake2 message).
func (h *Handshake) Start() ([]byte, error) {
	return h.suite.Start()
}

// ProcessPeer processes the peer's public value.
// Reference: Matter Core Spec 1.5, Section 4.14.1.2 (PASE Message Flow)
// For client role, this processes Y from Pake2.
// For server role, this processes X from Pake1.
func (h *Handshake) ProcessPeer(peerPublic []byte) error {
	return h.suite.ProcessPeer(peerPublic)
}

// Verify verifies the peer's confirmation MAC.
// Reference: Matter Core Spec 1.5, Section 4.14.1.3 (Key Confirmation)
// For client role, this verifies the server's MAC (CMac from Pake2).
// For server role, this verifies the client's MAC (SMac from Pake3).
func (h *Handshake) Verify(peerMAC []byte) error {
	return h.suite.VerifyConfirmation(peerMAC)
}

// GetConfirmation returns the local confirmation MAC to send to the peer.
// Reference: Matter Core Spec 1.5, Section 4.14.1.3 (Key Confirmation)
// For client role, this returns SMac (for Pake3).
// For server role, this returns CMac (for Pake2).
func (h *Handshake) GetConfirmation() ([]byte, error) {
	return h.suite.GetConfirmation()
}

// ExportKeys derives the session keys after successful handshake completion.
// Reference: Matter Core Spec 1.5, Section 4.14.1.4 (Session Key Generation)
// Returns (I2R key, R2I key, error).
func (h *Handshake) ExportKeys() ([]byte, []byte, error) {
	return h.suite.ExportKeys()
}
