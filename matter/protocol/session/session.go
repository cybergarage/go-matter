// Copyright (C) 2026 The go-matter Authors. All rights reserved.
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

package session

import (
	"github.com/cybergarage/go-matter/matter/io"
	"github.com/cybergarage/go-matter/matter/protocol/pase"
	"github.com/cybergarage/go-matter/matter/types"
)

// Transport is the underlying byte-oriented transport interface.
type Transport = io.Transport

// SessionKeys holds the keys and identifiers for an established PASE session.
type SessionKeys = pase.SessionKeys

// NodeID is a Matter node identifier.
type NodeID = types.NodeID

// SessionID is a Matter session identifier.
type SessionID = types.SessionID

// SecureSession wraps a Transport and applies AES-128-CCM encryption and decryption
// using the keys established during a PASE handshake.
// 4.7. Encryption.
type SecureSession interface {
	// Transmit encrypts payload (protocol header + application payload) and sends it
	// over the underlying transport using the I2R (Initiator-to-Responder) key.
	// The caller provides raw (unencrypted) protocol-header and payload bytes.
	Transmit(payload []byte) error
	// Receive reads one message from the underlying transport, decrypts the payload
	// using the R2I (Responder-to-Initiator) key, and returns the decrypted payload.
	Receive() ([]byte, error)
	// Transport returns the underlying raw transport.
	Transport() Transport
	// SessionKeys returns the session keys for this session.
	SessionKeys() SessionKeys
}
