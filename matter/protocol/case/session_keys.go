package caseprotocol

import "github.com/cybergarage/go-matter/matter/protocol/session"

type sessionKeys struct {
	i2rKey             []byte
	r2iKey             []byte
	challenge          []byte
	initiatorSessionID session.SessionID
	responderSessionID session.SessionID
	localNodeID        session.NodeID
	peerNodeID         session.NodeID
}

func newSessionKeys(i2rKey, r2iKey, challenge []byte, initiatorSessionID, responderSessionID session.SessionID, localNodeID, peerNodeID session.NodeID) session.SessionKeys {
	return &sessionKeys{
		i2rKey:             cloneBytes(i2rKey),
		r2iKey:             cloneBytes(r2iKey),
		challenge:          cloneBytes(challenge),
		initiatorSessionID: initiatorSessionID,
		responderSessionID: responderSessionID,
		localNodeID:        localNodeID,
		peerNodeID:         peerNodeID,
	}
}

func (k *sessionKeys) I2RKey() []byte { return cloneBytes(k.i2rKey) }
func (k *sessionKeys) R2IKey() []byte { return cloneBytes(k.r2iKey) }
func (k *sessionKeys) InitiatorSessionID() session.SessionID {
	return k.initiatorSessionID
}
func (k *sessionKeys) ResponderSessionID() session.SessionID {
	return k.responderSessionID
}
func (k *sessionKeys) LocalNodeID() session.NodeID { return k.localNodeID }
func (k *sessionKeys) PeerNodeID() session.NodeID  { return k.peerNodeID }

// AttestationChallenge returns the third key the session keys derivation
// yields (4.14.2.6), which a CSRRequest for UpdateNOC over CASE is signed
// with.
func (k *sessionKeys) AttestationChallenge() []byte { return cloneBytes(k.challenge) }
