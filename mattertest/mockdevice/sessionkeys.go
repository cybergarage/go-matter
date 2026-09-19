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

package mockdevice

import "github.com/cybergarage/go-matter/matter/protocol/session"

// simpleSessionKeys is a minimal session.SessionKeys implementation this
// package constructs directly from its own PASE/CASE key-derivation output,
// holding the keys/identifiers exactly as a commissioner (initiator) would
// see them.
type simpleSessionKeys struct {
	i2rKey               []byte
	r2iKey               []byte
	attestationChallenge []byte
	initiatorSessionID   session.SessionID
	responderSessionID   session.SessionID
	localNodeID          session.NodeID
	peerNodeID           session.NodeID
}

func (k simpleSessionKeys) I2RKey() []byte                        { return k.i2rKey }
func (k simpleSessionKeys) R2IKey() []byte                        { return k.r2iKey }
func (k simpleSessionKeys) InitiatorSessionID() session.SessionID { return k.initiatorSessionID }
func (k simpleSessionKeys) ResponderSessionID() session.SessionID { return k.responderSessionID }
func (k simpleSessionKeys) LocalNodeID() session.NodeID           { return k.localNodeID }
func (k simpleSessionKeys) PeerNodeID() session.NodeID            { return k.peerNodeID }
func (k simpleSessionKeys) AttestationChallenge() []byte          { return k.attestationChallenge }

// swapRoleSessionKeys adapts a session.SessionKeys built from the
// commissioner's (initiator's) point of view into the mirror-image one this
// mock device (the responder) needs, so it can reuse
// session.SecureSession's Transmit/Receive unmodified.
//
// session.SecureSession (matter/protocol/session/session_impl.go) hardcodes
// initiator-side direction: Transmit always encrypts with I2RKey() and
// stamps ResponderSessionID() in the outgoing header (the receiver's own
// session ID); Receive always decrypts with R2IKey() and expects
// InitiatorSessionID() in the incoming header. For the device — which
// transmits using what the spec calls the R2I key and stamps the
// commissioner's (Initiator) session ID, and receives messages stamped with
// its own (Responder) session ID, decrypting with the I2R key — every one
// of those needs its mirror value. Node IDs swap the same way: this side's
// "local" identity is the original's "peer", and vice versa.
func swapRoleSessionKeys(k session.SessionKeys) session.SessionKeys {
	return simpleSessionKeys{
		i2rKey:               k.R2IKey(),
		r2iKey:               k.I2RKey(),
		attestationChallenge: k.AttestationChallenge(),
		initiatorSessionID:   k.ResponderSessionID(),
		responderSessionID:   k.InitiatorSessionID(),
		localNodeID:          k.PeerNodeID(),
		peerNodeID:           k.LocalNodeID(),
	}
}
