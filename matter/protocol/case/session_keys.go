package caseprotocol

import "github.com/cybergarage/go-matter/matter/protocol/session"

type sessionKeys struct {
	i2rKey             []byte
	r2iKey             []byte
	initiatorSessionID session.SessionID
	responderSessionID session.SessionID
	localNodeID        session.NodeID
	peerNodeID         session.NodeID
}

func newSessionKeys(i2rKey, r2iKey []byte, initiatorSessionID, responderSessionID session.SessionID, localNodeID, peerNodeID session.NodeID) session.SessionKeys {
	return &sessionKeys{
		i2rKey:             cloneBytes(i2rKey),
		r2iKey:             cloneBytes(r2iKey),
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

// AttestationChallenge always returns nil for a CASE session; see the
// session.SessionKeys.AttestationChallenge doc comment.
func (k *sessionKeys) AttestationChallenge() []byte { return nil }
