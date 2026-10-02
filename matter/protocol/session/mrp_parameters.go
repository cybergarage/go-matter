// Copyright (C) 2026 The go-matter Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package session

import (
	"time"
)

// MRPParameters are the session parameters a peer announces for the
// Message Reliability Protocol while the session is established (4.13.1.
// Session Parameters): how long it may take to answer when idle and when
// active, and how long it stays active after a message.
type MRPParameters struct {
	// IdleInterval is SESSION_IDLE_INTERVAL (SII), the retransmission
	// interval of the peer when idle.
	IdleInterval time.Duration
	// ActiveInterval is SESSION_ACTIVE_INTERVAL (SAI), the retransmission
	// interval of the peer when active.
	ActiveInterval time.Duration
	// ActiveThreshold is SESSION_ACTIVE_THRESHOLD (SAT), how long the
	// peer stays active after it sent a message.
	ActiveThreshold time.Duration
}

// Default session parameters, of a peer which announces none (4.13.1).
const (
	DefaultSessionIdleInterval    = 500 * time.Millisecond
	DefaultSessionActiveInterval  = 300 * time.Millisecond
	DefaultSessionActiveThreshold = 4000 * time.Millisecond
	// MaxSessionInterval is the largest SII or SAI a peer may announce:
	// one hour.
	MaxSessionInterval = time.Hour
)

// DefaultMRPParameters returns the parameters of a peer which announces
// none.
func DefaultMRPParameters() MRPParameters {
	return MRPParameters{
		IdleInterval:    DefaultSessionIdleInterval,
		ActiveInterval:  DefaultSessionActiveInterval,
		ActiveThreshold: DefaultSessionActiveThreshold,
	}
}

// WithDefaults returns p with each parameter the peer did not announce,
// or announced out of range, set to its default.
func (p MRPParameters) WithDefaults() MRPParameters {
	if p.IdleInterval <= 0 || MaxSessionInterval < p.IdleInterval {
		p.IdleInterval = DefaultSessionIdleInterval
	}
	if p.ActiveInterval <= 0 || MaxSessionInterval < p.ActiveInterval {
		p.ActiveInterval = DefaultSessionActiveInterval
	}
	if p.ActiveThreshold <= 0 {
		p.ActiveThreshold = DefaultSessionActiveThreshold
	}
	return p
}

// WithPeerMRPParameters makes the session's retransmissions (see
// WithRetransmission) follow the parameters the peer announced: they start
// from its active interval while the peer is active, that is within its
// active threshold of the last message received from it, and from its
// idle interval otherwise (4.12.8. Retransmissions).
func WithPeerMRPParameters(p MRPParameters) SecureSessionOption {
	return func(s *secureSession) {
		p = p.WithDefaults()
		s.peerMRP = &p
	}
}

// PeerMRPParameters returns the parameters the peer of sess announced, as
// set with WithPeerMRPParameters; ok is false when none were set.
func PeerMRPParameters(sess SecureSession) (MRPParameters, bool) {
	s, ok := sess.(*secureSession)
	if !ok || s.peerMRP == nil {
		return MRPParameters{}, false
	}
	return *s.peerMRP, true
}
