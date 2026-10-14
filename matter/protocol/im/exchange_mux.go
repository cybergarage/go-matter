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

package im

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter/encoding/message"
	"github.com/cybergarage/go-matter/matter/protocol/session"
)

// DefaultResponseTimeout bounds how long an ExchangeMux waits for the
// response of an exchange this node initiated.
const DefaultResponseTimeout = 30 * time.Second

var (
	// ErrMuxClosed is returned once an ExchangeMux is closed.
	ErrMuxClosed = errors.New("im: the session is closed")
	// ErrResponseTimeout is returned when no response arrives on an
	// exchange within the response timeout.
	ErrResponseTimeout = errors.New("im: no response within the response timeout")
)

// unclaimedMessageLifetime is how long a message of an exchange nobody
// waits for is kept, such as a late retransmission of an old response.
const unclaimedMessageLifetime = time.Minute

// ExchangeMux shares one secure session between the exchanges this node
// initiates, such as Read, Write, Invoke and Subscribe requests, and the
// exchanges the peer initiates to deliver the reports of its subscriptions
// (4.10. Message Exchanges, 8.5. Subscribe Interaction). One goroutine reads
// the session: a response is handed to whoever waits for its exchange, and
// a report to its subscription. It is a SecureSession itself, so the
// Read, Write and Invoke functions of this package work over it unchanged.
type ExchangeMux struct {
	sess     SecureSession
	timeout  time.Duration
	exchange atomic.Uint32

	mutex   sync.Mutex
	queue   []queuedMessage
	changed chan struct{}
	subs    map[uint32]*Subscription
	err     error
	closed  bool
	done    chan struct{}
}

type queuedMessage struct {
	raw      []byte
	exchange message.ExchangeID
	at       time.Time
}

// ExchangeMuxOption configures an ExchangeMux.
type ExchangeMuxOption func(*ExchangeMux)

// WithResponseTimeout sets how long the mux waits for the response of an
// exchange. Defaults to DefaultResponseTimeout.
func WithResponseTimeout(d time.Duration) ExchangeMuxOption {
	return func(m *ExchangeMux) {
		m.timeout = d
	}
}

// NewExchangeMux starts reading sess. From then on, sess must be read only
// through the mux, and its transport must not time a read out by itself.
func NewExchangeMux(sess SecureSession, opts ...ExchangeMuxOption) *ExchangeMux {
	m := &ExchangeMux{
		sess:    sess,
		timeout: DefaultResponseTimeout,
		mutex:   sync.Mutex{},
		queue:   nil,
		changed: make(chan struct{}),
		subs:    map[uint32]*Subscription{},
		err:     nil,
		closed:  false,
		done:    make(chan struct{}),
	}
	for _, opt := range opts {
		opt(m)
	}
	m.exchange.Store(uint32(message.NewFirstExchangeID()))
	go m.read()
	return m
}

// NewExchangeID returns the ID of a new exchange this node initiates: the
// first is random, and each one after it the next (4.10.2), so that
// concurrent exchanges do not share an ID.
func (m *ExchangeMux) NewExchangeID() message.ExchangeID {
	return message.ExchangeID(m.exchange.Add(1)) // nolint: gosec // ExchangeID rolls over at 16 bits
}

// Transmit sends payload on the session.
func (m *ExchangeMux) Transmit(payload []byte) error {
	return m.sess.Transmit(payload)
}

// Receive returns the next message which no subscription took, of any
// exchange, waiting up to the response timeout.
func (m *ExchangeMux) Receive() ([]byte, error) {
	return m.receive(context.Background(), func(queuedMessage) bool { return true })
}

// ReceiveExchange returns the next message of the exchange, waiting up to
// the response timeout.
func (m *ExchangeMux) ReceiveExchange(exchange message.ExchangeID) ([]byte, error) {
	return m.ReceiveExchangeContext(context.Background(), exchange)
}

// ReceiveExchangeContext is ReceiveExchange which also returns when ctx is
// done.
func (m *ExchangeMux) ReceiveExchangeContext(ctx context.Context, exchange message.ExchangeID) ([]byte, error) {
	return m.receive(ctx, func(q queuedMessage) bool { return q.exchange == exchange })
}

// Unwrap returns the session the mux reads, so that the session package's
// helpers, such as session.PeerMRPParameters, see through the mux. It must
// not be read directly.
func (m *ExchangeMux) Unwrap() SecureSession {
	return m.sess
}

// Transport returns the session's transport.
func (m *ExchangeMux) Transport() session.Transport {
	return m.sess.Transport()
}

// SessionKeys returns the session's keys.
func (m *ExchangeMux) SessionKeys() session.SessionKeys {
	return m.sess.SessionKeys()
}

// Done is closed when the mux stops reading the session, after Close or
// when the session fails.
func (m *ExchangeMux) Done() <-chan struct{} {
	return m.done
}

// Err returns why the mux stopped reading the session, or nil while it
// reads.
func (m *ExchangeMux) Err() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	return m.err
}

// Close stops the mux and the subscriptions on it. The caller closes the
// session's transport, which ends the read in progress.
func (m *ExchangeMux) Close() error {
	m.mutex.Lock()
	if m.closed {
		m.mutex.Unlock()
		return nil
	}
	m.closed = true
	if m.err == nil {
		m.err = ErrMuxClosed
	}
	subs := m.subscriptionsLocked()
	m.broadcastLocked()
	m.mutex.Unlock()
	for _, sub := range subs {
		sub.end(nil)
	}
	return nil
}

func (m *ExchangeMux) receive(ctx context.Context, match func(queuedMessage) bool) ([]byte, error) {
	timer := time.NewTimer(m.timeout)
	defer timer.Stop()
	for {
		m.mutex.Lock()
		m.pruneLocked()
		for i, q := range m.queue {
			if match(q) {
				m.queue = append(m.queue[:i], m.queue[i+1:]...)
				m.mutex.Unlock()
				return q.raw, nil
			}
		}
		if m.err != nil {
			err := m.err
			m.mutex.Unlock()
			return nil, err
		}
		changed := m.changed
		m.mutex.Unlock()
		select {
		case <-changed:
		case <-timer.C:
			return nil, ErrResponseTimeout
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// read is the only reader of the session.
func (m *ExchangeMux) read() {
	defer close(m.done)
	for {
		raw, err := m.sess.Receive()
		if err != nil {
			m.fail(err)
			return
		}
		hdr, err := message.NewProtocolHeaderFromBytes(raw)
		if err != nil {
			log.Debugf("im: mux: drop a message with a malformed protocol header: %v", err)
			continue
		}
		if hdr.IsInitiator() && hdr.ProtocolID() == message.InteractionModel {
			// The peer opened this exchange.
			m.servePeerExchange(hdr, raw)
			continue
		}
		m.mutex.Lock()
		m.queue = append(m.queue, queuedMessage{raw: raw, exchange: hdr.ExchangeID(), at: time.Now()})
		m.broadcastLocked()
		m.mutex.Unlock()
	}
}

// servePeerExchange answers a message on an exchange the peer opened: a
// subscription report, or anything else, which a commissioner does not
// serve.
func (m *ExchangeMux) servePeerExchange(hdr message.ProtocolHeader, raw []byte) {
	if !hdr.Opcode().IsReportDataMessage() {
		log.Debugf("im: mux: the peer opened an exchange with opcode %v, which is not served", hdr.Opcode())
		if err := sendStatusResponse(m.sess, hdr.ExchangeID(), StatusInvalidAction); err != nil {
			log.Warnf("im: mux: %v", err)
		}
		return
	}
	report, err := decodeReportData(raw)
	if err != nil {
		log.Warnf("im: mux: %v", err)
		if err := sendStatusResponse(m.sess, hdr.ExchangeID(), StatusInvalidAction); err != nil {
			log.Warnf("im: mux: %v", err)
		}
		return
	}
	m.mutex.Lock()
	sub := m.subs[report.subscriptionID]
	m.mutex.Unlock()
	if !report.hasSubscriptionID || sub == nil {
		// Tells the publisher to end a subscription this node no longer
		// has (8.5.2).
		if err := sendStatusResponse(m.sess, hdr.ExchangeID(), StatusInvalidSubscription); err != nil {
			log.Warnf("im: mux: %v", err)
		}
		return
	}
	if !report.suppressResponse || report.moreChunks {
		if err := sendStatusResponse(m.sess, hdr.ExchangeID(), StatusSuccess); err != nil {
			log.Warnf("im: mux: %v", err)
		}
	}
	sub.received(hdr.ExchangeID(), report)
}

func (m *ExchangeMux) register(id uint32, sub *Subscription) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if m.err != nil {
		return m.err
	}
	m.subs[id] = sub
	return nil
}

func (m *ExchangeMux) unregister(id uint32, sub *Subscription) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if m.subs[id] == sub {
		delete(m.subs, id)
	}
}

func (m *ExchangeMux) fail(err error) {
	m.mutex.Lock()
	if m.err == nil {
		m.err = fmt.Errorf("im: the session failed: %w", err)
	}
	closed := m.closed
	subs := m.subscriptionsLocked()
	m.broadcastLocked()
	m.mutex.Unlock()
	if closed {
		return
	}
	for _, sub := range subs {
		sub.end(m.Err())
	}
}

func (m *ExchangeMux) subscriptionsLocked() []*Subscription {
	subs := make([]*Subscription, 0, len(m.subs))
	for _, sub := range m.subs {
		subs = append(subs, sub)
	}
	return subs
}

func (m *ExchangeMux) broadcastLocked() {
	close(m.changed)
	m.changed = make(chan struct{})
}

func (m *ExchangeMux) pruneLocked() {
	now := time.Now()
	kept := m.queue[:0]
	for _, q := range m.queue {
		if now.Sub(q.at) < unclaimedMessageLifetime {
			kept = append(kept, q)
		}
	}
	m.queue = kept
}

// exchangeReceiver is a session which hands out the messages of one
// exchange, such as an ExchangeMux.
type exchangeReceiver interface {
	ReceiveExchange(exchange message.ExchangeID) ([]byte, error)
}

// exchangeAllocator is a session which allocates the IDs of the exchanges
// this node initiates, such as an ExchangeMux.
type exchangeAllocator interface {
	NewExchangeID() message.ExchangeID
}

// newExchangeID returns the ID of a new exchange on sess: from sess when it
// allocates them, else a random one.
func newExchangeID(sess SecureSession) message.ExchangeID {
	if a, ok := sess.(exchangeAllocator); ok {
		return a.NewExchangeID()
	}
	return message.NewFirstExchangeID()
}
