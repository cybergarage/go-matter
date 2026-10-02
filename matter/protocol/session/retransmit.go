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
	"context"
	"math"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter/encoding/message"
)

// Message Reliability Protocol parameters (Matter Core 4.12.8): a
// reliable message unacknowledged after the retransmission timeout is
// sent again, with a timeout growing by MRP_BACKOFF_BASE after the first
// MRP_BACKOFF_THRESHOLD retransmissions, up to MRP_MAX_TRANSMISSIONS
// transmissions in all.
const (
	// DefaultActiveRetransmitInterval is the retransmission interval of a
	// peer which advertises no SessionActiveInterval (SAI, 300 ms).
	DefaultActiveRetransmitInterval = 300 * time.Millisecond
	// DefaultMaxTransmissions is MRP_MAX_TRANSMISSIONS.
	DefaultMaxTransmissions = 5

	mrpBackoffBase      = 1.6
	mrpBackoffJitter    = 0.25
	mrpBackoffMargin    = 1.1
	mrpBackoffThreshold = 1
)

// WithRetransmission makes the session retransmit its reliable messages
// until the peer acknowledges them, every interval backed off, up to
// maxTransmissions transmissions in all. MRP applies to sessions
// over UDP only: BTP and TCP are reliable already.
func WithRetransmission(interval time.Duration, maxTransmissions int) SecureSessionOption {
	return func(s *secureSession) {
		s.retransmit = &retransmitter{
			mutex:            sync.Mutex{},
			interval:         interval,
			maxTransmissions: maxTransmissions,
			pending:          map[message.MessageCounter]*pendingMessage{},
			stopped:          false,
		}
	}
}

// WithUndeliveredHandler sets the function called with the protocol
// header of a reliable message the peer did not acknowledge after the last
// retransmission (4.12.8.1), as an Interaction Model server ends the
// subscription whose report it was.
func WithUndeliveredHandler(h func(message.ProtocolHeader)) SecureSessionOption {
	return func(s *secureSession) {
		s.onUndelivered = h
	}
}

// StopRetransmissions stops retransmitting the messages sess sent, as when
// the session closes; the messages sess sends afterwards are sent once.
func StopRetransmissions(sess SecureSession) {
	if s, ok := sess.(*secureSession); ok && s.retransmit != nil {
		s.retransmit.stop()
	}
}

// retransmitter keeps the reliable messages a session sent which the peer
// has not acknowledged yet (the retransmission table).
type retransmitter struct {
	mutex            sync.Mutex
	interval         time.Duration
	maxTransmissions int
	pending          map[message.MessageCounter]*pendingMessage
	stopped          bool
}

type pendingMessage struct {
	wire          []byte
	header        message.ProtocolHeader
	transmissions int
	// interval is the base retransmission interval, chosen when the
	// message was first sent.
	interval time.Duration
	timer    *time.Timer
}

// baseInterval returns the interval a message's retransmissions start
// from: the peer's active interval while it is active, its idle interval
// otherwise, when it announced its parameters, and the session's interval
// when it did not (4.12.8).
func (r *retransmitter) baseInterval(s *secureSession) time.Duration {
	if s.peerMRP == nil {
		return r.interval
	}
	if time.Since(time.Unix(0, s.lastReceived.Load())) < s.peerMRP.ActiveThreshold {
		return s.peerMRP.ActiveInterval
	}
	return s.peerMRP.IdleInterval
}

// backoff returns the time to wait for an acknowledgement after a
// message's transmissions-th transmission, from the base interval.
func backoff(interval time.Duration, transmissions int) time.Duration {
	n := max(0, transmissions-1-mrpBackoffThreshold)
	d := float64(interval) * mrpBackoffMargin * math.Pow(mrpBackoffBase, float64(n)) * (1 + rand.Float64()*mrpBackoffJitter) // nolint: gosec // jitter
	return time.Duration(d)
}

// sent records a reliable message s sent, and schedules its
// retransmission.
func (r *retransmitter) sent(s *secureSession, counter message.MessageCounter, header message.ProtocolHeader, wire []byte) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	if r.stopped {
		return
	}
	p := &pendingMessage{wire: wire, header: header, transmissions: 1, interval: r.baseInterval(s), timer: nil}
	r.pending[counter] = p
	p.timer = time.AfterFunc(backoff(p.interval, 1), func() { r.expire(s, counter) })
}

// expire retransmits an unacknowledged message, or gives it up after the
// last transmission.
func (r *retransmitter) expire(s *secureSession, counter message.MessageCounter) {
	r.mutex.Lock()
	p, ok := r.pending[counter]
	if !ok {
		r.mutex.Unlock()
		return
	}
	if r.maxTransmissions <= p.transmissions {
		delete(r.pending, counter)
		transmissions := p.transmissions
		r.mutex.Unlock()
		log.Infof("session: message %d (exchange %d, opcode 0x%02X) was not acknowledged after %d transmissions",
			counter, p.header.ExchangeID(), uint8(p.header.Opcode()), transmissions)
		if s.onUndelivered != nil {
			s.onUndelivered(p.header)
		}
		return
	}
	p.transmissions++
	transmissions := p.transmissions
	wire := p.wire
	p.timer = time.AfterFunc(backoff(p.interval, transmissions), func() { r.expire(s, counter) })
	r.mutex.Unlock()
	log.Debugf("session: retransmitting message %d (transmission %d)", counter, transmissions)
	if err := s.t.Transmit(context.Background(), wire); err != nil {
		log.Debugf("session: retransmit message %d: %v", counter, err)
	}
}

// acknowledged removes a message the peer acknowledged.
func (r *retransmitter) acknowledged(counter message.MessageCounter) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	if p, ok := r.pending[counter]; ok {
		p.timer.Stop()
		delete(r.pending, counter)
	}
}

// stop gives up every pending message, and the messages sent afterwards.
func (r *retransmitter) stop() {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.stopped = true
	for counter, p := range r.pending {
		p.timer.Stop()
		delete(r.pending, counter)
	}
}
