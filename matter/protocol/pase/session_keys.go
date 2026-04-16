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

import "github.com/cybergarage/go-matter/matter/types"

// SessionKeys represents the session keys derived after a successful PASE session.
// 4.14.1.3. Key Derivation.
type SessionKeys interface {
	// I2RKey returns the initiator-to-responder AES-CCM key.
	I2RKey() []byte
	// R2IKey returns the responder-to-initiator AES-CCM key.
	R2IKey() []byte
	// AttestationChallenge returns the attestation challenge.
	AttestationChallenge() []byte
	// InitiatorSessionID returns the session ID chosen by the initiator.
	// 4.13.2.4. Choosing Secure Unicast Session Identifiers.
	InitiatorSessionID() SessionID
	// ResponderSessionID returns the session ID chosen by the responder.
	// 4.13.2.4. Choosing Secure Unicast Session Identifiers.
	ResponderSessionID() SessionID
	// LocalNodeID returns the source node ID the initiator used in the PASE handshake.
	LocalNodeID() NodeID
}

// SessionID represents a session identifier.
type SessionID = types.SessionID

// NodeID represents a node identifier.
type NodeID = types.NodeID

type sessionKeys struct {
	i2rKey               []byte
	r2iKey               []byte
	attestationChallenge []byte
	initiatorSessionID   SessionID
	responderSessionID   SessionID
	localNodeID          NodeID
}

func newSessionKeys(i2rKey, r2iKey, attestationChallenge []byte, initiatorSID, responderSID SessionID, localNodeID NodeID) SessionKeys {
	return &sessionKeys{
		i2rKey:               cloneBytes(i2rKey),
		r2iKey:               cloneBytes(r2iKey),
		attestationChallenge: cloneBytes(attestationChallenge),
		initiatorSessionID:   initiatorSID,
		responderSessionID:   responderSID,
		localNodeID:          localNodeID,
	}
}

func (keys *sessionKeys) I2RKey() []byte {
	return cloneBytes(keys.i2rKey)
}

func (keys *sessionKeys) R2IKey() []byte {
	return cloneBytes(keys.r2iKey)
}

func (keys *sessionKeys) AttestationChallenge() []byte {
	return cloneBytes(keys.attestationChallenge)
}

func (keys *sessionKeys) InitiatorSessionID() SessionID {
	return keys.initiatorSessionID
}

func (keys *sessionKeys) ResponderSessionID() SessionID {
	return keys.responderSessionID
}

func (keys *sessionKeys) LocalNodeID() NodeID {
	return keys.localNodeID
}

func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	cp := make([]byte, len(b))
	copy(cp, b)
	return cp
}
