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
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter/encoding/message"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
)

// minMaxInterval is the shortest MaxInterval the server grants, so that a
// peer asking for 0 does not make it report without pause.
const minMaxInterval = time.Second

// subscribeRequest is a decoded SubscribeRequestMessage (10.7.4).
type subscribeRequest struct {
	keepSubscriptions bool
	minIntervalFloor  time.Duration
	maxIntervalCeil   time.Duration
	paths             []requestedPath
	fabricFiltered    bool
}

func decodeSubscribeRequest(body []byte) (subscribeRequest, error) {
	var req subscribeRequest
	dec, err := openTopLevel(body)
	if err != nil {
		return req, err
	}
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			break
		}
		tag, _ := contextNumber(elem)
		switch {
		case tag == 0 && !elem.Type().IsContainer():
			req.keepSubscriptions, _ = elem.Bool()
		case tag == 1 && !elem.Type().IsContainer():
			v, _ := elem.Unsigned()
			req.minIntervalFloor = time.Duration(v) * time.Second
		case tag == 2 && !elem.Type().IsContainer():
			v, _ := elem.Unsigned()
			req.maxIntervalCeil = time.Duration(v) * time.Second
		case tag == 3 && elem.Type().IsArray():
			for dec.Next() {
				pathElem := dec.Element()
				if pathElem.Type().IsEndOfContainer() {
					break
				}
				if !pathElem.Type().IsContainer() {
					return req, errors.New("attribute-path-IB is not a list")
				}
				p, err := decodeAttributePathIB(dec)
				if err != nil {
					return req, err
				}
				req.paths = append(req.paths, p)
			}
		case tag == 7 && !elem.Type().IsContainer():
			req.fabricFiltered, _ = elem.Bool()
		case elem.Type().IsContainer():
			if err := skipContainer(dec); err != nil {
				return req, err
			}
		}
	}
	return req, dec.Error()
}

// matches reports whether a requested path, whose nil fields are
// wildcards, covers a concrete path.
func (p requestedPath) matches(ap AttributePath) bool {
	return (p.endpoint == nil || *p.endpoint == ap.Endpoint) &&
		(p.cluster == nil || *p.cluster == ap.Cluster) &&
		(p.attribute == nil || *p.attribute == ap.Attribute)
}

// subscription is an active subscription of a peer (8.5): the server
// reports the attributes of its paths which changed, at most every
// minInterval, and at least every maxInterval, empty if nothing did.
type subscription struct {
	id             uint32
	server         *Server
	sess           SecureSession
	paths          []requestedPath
	fabricFiltered bool
	minInterval    time.Duration
	maxInterval    time.Duration

	mutex sync.Mutex
	dirty map[AttributePath]bool
	// exchange is the exchange of the latest report.
	exchange message.ExchangeID
	wake     chan struct{}
	done     chan struct{}
	once     sync.Once
}

type pendingKey struct {
	sess     SecureSession
	exchange message.ExchangeID
}

type subscriptions struct {
	mutex   sync.Mutex
	active  map[uint32]*subscription
	pending map[pendingKey]*subscription
}

func newSubscriptions() *subscriptions {
	return &subscriptions{
		mutex:   sync.Mutex{},
		active:  map[uint32]*subscription{},
		pending: map[pendingKey]*subscription{},
	}
}

func newSubscriptionID() uint32 {
	var b [4]byte
	for {
		if _, err := rand.Read(b[:]); err == nil {
			if id := binary.LittleEndian.Uint32(b[:]); id != 0 {
				return id
			}
		}
	}
}

// serveSubscribe starts a subscription (8.5.1): it answers the
// SubscribeRequest with a priming report of every subscribed attribute,
// and finishes with a SubscribeResponse once the peer acknowledges the
// report with a StatusResponse.
func (s *Server) serveSubscribe(sess SecureSession, exchange message.ExchangeID, body []byte) error {
	req, err := decodeSubscribeRequest(body)
	if err != nil {
		if sendErr := sendStatusResponse(sess, exchange, StatusInvalidAction); sendErr != nil {
			return sendErr
		}
		return &decodeError{fmt.Errorf("im: decode SubscribeRequest: %w", err)}
	}
	if !req.keepSubscriptions {
		s.EndSession(sess)
	}
	maxInterval := max(req.maxIntervalCeil, req.minIntervalFloor, minMaxInterval)
	sub := &subscription{
		id:             newSubscriptionID(),
		server:         s,
		sess:           sess,
		paths:          req.paths,
		fabricFiltered: req.fabricFiltered,
		minInterval:    req.minIntervalFloor,
		maxInterval:    maxInterval,
		mutex:          sync.Mutex{},
		dirty:          map[AttributePath]bool{},
		exchange:       exchange,
		wake:           make(chan struct{}, 1),
		done:           make(chan struct{}),
		once:           sync.Once{},
	}
	payload, err := encodeReportDataMessage(s.readReports(sess, req.paths, req.fabricFiltered, nil), &sub.id, false)
	if err != nil {
		return err
	}
	s.subs.mutex.Lock()
	s.subs.pending[pendingKey{sess: sess, exchange: exchange}] = sub
	s.subs.mutex.Unlock()
	return sendIMResponse(sess, exchange, message.ReportDataMessage, payload)
}

// serveStatusResponse finishes the subscription whose priming report a
// StatusResponse acknowledges; any other StatusResponse, such as one for a
// report of an active subscription, needs nothing.
func (s *Server) serveStatusResponse(sess SecureSession, exchange message.ExchangeID, body []byte) error {
	key := pendingKey{sess: sess, exchange: exchange}
	s.subs.mutex.Lock()
	sub, ok := s.subs.pending[key]
	delete(s.subs.pending, key)
	s.subs.mutex.Unlock()
	if !ok {
		return nil
	}
	status, err := parseStatusResponseMessage(body)
	if err != nil {
		return &decodeError{fmt.Errorf("im: decode StatusResponse: %w", err)}
	}
	if status.IMStatus != uint8(StatusSuccess) {
		log.Infof("im: subscription %d refused its priming report: status 0x%02X", sub.id, status.IMStatus)
		return nil
	}
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	enc.PutUnsigned4(tlv.NewContextTag(0), sub.id)
	enc.PutUnsigned2(tlv.NewContextTag(2), uint16(min(sub.maxInterval/time.Second, 0xFFFF))) // nolint: gosec // bounded above
	enc.PutUnsigned1(tlv.NewContextTag(interactionModelRevisionTag), interactionModelRevision)
	if err := enc.EndContainer(); err != nil {
		return err
	}
	// The subscription is active before the peer learns it is: a change
	// right after the SubscribeResponse is reported, not lost.
	s.subs.mutex.Lock()
	s.subs.active[sub.id] = sub
	s.subs.mutex.Unlock()
	if err := sendIMResponse(sess, exchange, message.SubscribeResponseMessage, enc.Bytes()); err != nil {
		s.endSubscription(sub.id)
		return err
	}
	go sub.run()
	return nil
}

// NotifyAttributeChanged tells the server an attribute changed, so the
// subscriptions which cover it report it.
func (s *Server) NotifyAttributeChanged(path AttributePath) {
	s.subs.mutex.Lock()
	defer s.subs.mutex.Unlock()
	for _, sub := range s.subs.active {
		sub.changed(path)
	}
	// A change after a priming report is reported once the subscription
	// is established.
	for _, sub := range s.subs.pending {
		sub.changed(path)
	}
}

// EndSession ends the subscriptions of a session, as when it closes.
func (s *Server) EndSession(sess SecureSession) {
	s.subs.mutex.Lock()
	defer s.subs.mutex.Unlock()
	for id, sub := range s.subs.active {
		if sub.sess == sess {
			sub.stop()
			delete(s.subs.active, id)
		}
	}
	for key := range s.subs.pending {
		if key.sess == sess {
			delete(s.subs.pending, key)
		}
	}
}

func (sub *subscription) changed(path AttributePath) {
	for _, p := range sub.paths {
		if !p.matches(path) {
			continue
		}
		sub.mutex.Lock()
		sub.dirty[path] = true
		sub.mutex.Unlock()
		select {
		case sub.wake <- struct{}{}:
		default:
		}
		return
	}
}

func (sub *subscription) stop() {
	sub.once.Do(func() { close(sub.done) })
}

// run reports until the subscription ends: the changed attributes once
// minInterval has passed since the last report, and an empty report when
// maxInterval passes without one.
func (sub *subscription) run() {
	last := time.Now()
	keepAlive := time.NewTimer(sub.maxInterval)
	defer keepAlive.Stop()
	for {
		select {
		case <-sub.done:
			return
		case <-keepAlive.C:
		case <-sub.wake:
			if wait := time.Until(last.Add(sub.minInterval)); 0 < wait {
				select {
				case <-sub.done:
					return
				case <-time.After(wait):
				}
			}
		}
		sub.mutex.Lock()
		dirty := sub.dirty
		sub.dirty = map[AttributePath]bool{}
		sub.mutex.Unlock()
		if err := sub.report(dirty); err != nil {
			log.Warnf("im: subscription %d: %v", sub.id, err)
			sub.server.endSubscription(sub.id)
			return
		}
		last = time.Now()
		if !keepAlive.Stop() {
			select {
			case <-keepAlive.C:
			default:
			}
		}
		keepAlive.Reset(sub.maxInterval)
	}
}

// report sends a ReportData of the changed attributes on a new exchange.
func (sub *subscription) report(dirty map[AttributePath]bool) error {
	var reports []attributeReport
	if 0 < len(dirty) {
		reports = sub.server.readReports(sub.sess, sub.paths, sub.fabricFiltered, func(ap AttributePath) bool { return dirty[ap] })
	}
	payload, err := encodeReportDataMessage(reports, &sub.id, false)
	if err != nil {
		return err
	}
	exchange := message.NewFirstExchangeID()
	sub.mutex.Lock()
	sub.exchange = exchange
	sub.mutex.Unlock()
	return transmitOnExchange(sub.sess, message.ReportDataMessage, exchange, payload)
}

// Undelivered tells the server the peer of sess did not acknowledge a
// message the server sent it, whose protocol header is hdr. A subscription
// whose report, or priming report, the peer did not take ends (8.5.2,
// 4.12.8.1): the peer is gone, or has to subscribe again to learn what it
// missed.
func (s *Server) Undelivered(sess SecureSession, hdr message.ProtocolHeader) {
	if hdr.ProtocolID() != message.InteractionModel || hdr.Opcode() != message.ReportDataMessage {
		return
	}
	s.subs.mutex.Lock()
	defer s.subs.mutex.Unlock()
	if !hdr.IsInitiator() {
		// A priming report, on the peer's exchange.
		key := pendingKey{sess: sess, exchange: hdr.ExchangeID()}
		if sub, ok := s.subs.pending[key]; ok {
			log.Infof("im: subscription %d: the priming report was not delivered", sub.id)
			delete(s.subs.pending, key)
		}
		return
	}
	for id, sub := range s.subs.active {
		sub.mutex.Lock()
		match := sub.sess == sess && sub.exchange == hdr.ExchangeID()
		sub.mutex.Unlock()
		if match {
			log.Infof("im: subscription %d: a report was not delivered, ending it", id)
			sub.stop()
			delete(s.subs.active, id)
		}
	}
}

func (s *Server) endSubscription(id uint32) {
	s.subs.mutex.Lock()
	defer s.subs.mutex.Unlock()
	if sub, ok := s.subs.active[id]; ok {
		sub.stop()
		delete(s.subs.active, id)
	}
}
