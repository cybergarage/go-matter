package caseprotocol

import "github.com/cybergarage/go-matter/matter/protocol/session"

type sessionKeys struct {
	i2rKey             []byte
	r2iKey             []byte
	initiatorSessionID session.SessionID
	responderSessionID session.SessionID
	localNodeID        session.NodeID
}

func newSessionKeys(i2rKey, r2iKey []byte, initiatorSessionID, responderSessionID session.SessionID, localNodeID session.NodeID) session.SessionKeys {
	return &sessionKeys{
		i2rKey:             cloneBytes(i2rKey),
		r2iKey:             cloneBytes(r2iKey),
		initiatorSessionID: initiatorSessionID,
		responderSessionID: responderSessionID,
		localNodeID:        localNodeID,
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
