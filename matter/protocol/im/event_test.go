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
	"sync"
	"testing"
	"time"

	"github.com/cybergarage/go-matter/matter/encoding/message"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	"github.com/cybergarage/go-matter/matter/protocol/session"
)

// The event the tests publish: Switch (0x003B) InitialPress (0x01) on
// endpoint 1, whose data holds NewPosition (tag 0).
var switchPressPath = EventPath{Endpoint: 1, Cluster: 0x003B, Event: 0x01}

// testEvent is an event the publisher reports; delta reports its epoch
// timestamp as a delta from the event before it.
type testEvent struct {
	number    uint64
	timestamp uint64
	delta     bool
	position  uint8
}

// encodeEventReportData encodes a ReportData of events.
func encodeEventReportData(t *testing.T, subscriptionID *uint32, events []testEvent, more, suppress bool) []byte {
	t.Helper()
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	if subscriptionID != nil {
		enc.PutUnsigned4(tlv.NewContextTag(0), *subscriptionID)
	}
	enc.BeginArray(tlv.NewContextTag(2)) // EventReports
	var last uint64
	for _, e := range events {
		enc.BeginStructure(tlv.NewAnonymousTag()) // EventReportIB
		enc.BeginStructure(tlv.NewContextTag(1))  // EventDataIB
		enc.BeginList(tlv.NewContextTag(tagEventDataPath))
		enc.PutUnsigned2(tlv.NewContextTag(1), uint16(switchPressPath.Endpoint))
		_ = enc.PutUnsigned(tlv.NewContextTag(2), uint64(switchPressPath.Cluster))
		_ = enc.PutUnsigned(tlv.NewContextTag(3), uint64(switchPressPath.Event))
		_ = enc.EndContainer()
		enc.PutUnsigned8(tlv.NewContextTag(tagEventDataEventNumber), e.number)
		enc.PutUnsigned1(tlv.NewContextTag(tagEventDataPriority), uint8(EventPriorityInfo))
		if e.delta {
			enc.PutUnsigned8(tlv.NewContextTag(tagEventDataDeltaEpochTimestamp), e.timestamp-last)
		} else {
			enc.PutUnsigned8(tlv.NewContextTag(tagEventDataEpochTimestamp), e.timestamp)
		}
		last = e.timestamp
		enc.BeginStructure(tlv.NewContextTag(tagEventDataData))
		enc.PutUnsigned1(tlv.NewContextTag(0), e.position)
		_ = enc.EndContainer()
		_ = enc.EndContainer()
		_ = enc.EndContainer()
	}
	_ = enc.EndContainer()
	if more {
		enc.PutBool(tlv.NewContextTag(3), true)
	}
	if suppress {
		enc.PutBool(tlv.NewContextTag(4), true)
	}
	enc.PutUnsigned1(tlv.NewContextTag(interactionModelRevisionTag), interactionModelRevision)
	_ = enc.EndContainer()
	return enc.Bytes()
}

// eventPublisher is the peer of an ExchangeMux which answers event Reads
// and Subscribes from the events it keeps, as a node does.
type eventPublisher struct {
	t        *testing.T
	sess     SecureSession
	mutex    sync.Mutex
	events   []testEvent
	nextID   uint32
	requests chan *AttributeValue
	statuses chan message.ExchangeID
}

func startEventPublisher(t *testing.T, events []testEvent) (*eventPublisher, *ExchangeMux) {
	t.Helper()
	a2b := make(chan []byte, 64)
	b2a := make(chan []byte, 64)
	closed := make(chan struct{})
	client := session.NewSecureSession(&chanTransport{in: b2a, out: a2b, closed: closed}, serverTestKeys{})
	device := session.NewSecureSession(&chanTransport{in: a2b, out: b2a, closed: closed}, serverTestKeys{}, session.WithRole(session.RoleResponder))
	p := &eventPublisher{
		t:        t,
		sess:     device,
		mutex:    sync.Mutex{},
		events:   events,
		nextID:   100,
		requests: make(chan *AttributeValue, 8),
		statuses: make(chan message.ExchangeID, 16),
	}
	go p.serve()
	mux := NewExchangeMux(client, WithResponseTimeout(2*time.Second))
	t.Cleanup(func() {
		_ = mux.Close()
		close(closed)
	})
	return p, mux
}

// eventsFrom returns the kept events numbered min and up.
func (p *eventPublisher) eventsFrom(min uint64) []testEvent {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	var out []testEvent
	for _, e := range p.events {
		if min <= e.number {
			out = append(out, e)
		}
	}
	return out
}

func (p *eventPublisher) serve() {
	for {
		raw, err := p.sess.Receive()
		if err != nil {
			return
		}
		hdr, err := message.NewProtocolHeaderFromBytes(raw)
		if err != nil {
			continue
		}
		body, _ := messageBody(raw, hdr)
		switch hdr.Opcode() {
		case message.StatusResponseMessage:
			p.statuses <- hdr.ExchangeID()
		case message.ReadRequestMessage:
			req := decodeTestRequest(p.t, body)
			p.requests <- req
			events := p.eventsFrom(eventMinOf(req, 2))
			// Two chunks: the first event, then the others.
			_ = sendIMResponse(p.sess, hdr.ExchangeID(), message.ReportDataMessage, encodeEventReportData(p.t, nil, events[:1], true, false))
			p.awaitStatus(hdr.ExchangeID())
			_ = sendIMResponse(p.sess, hdr.ExchangeID(), message.ReportDataMessage, encodeEventReportData(p.t, nil, events[1:], false, true))
		case message.SubscribeRequestMessage:
			req := decodeTestRequest(p.t, body)
			p.requests <- req
			p.mutex.Lock()
			p.nextID++
			id := p.nextID
			p.mutex.Unlock()
			_ = sendIMResponse(p.sess, hdr.ExchangeID(), message.ReportDataMessage, encodeEventReportData(p.t, &id, p.eventsFrom(eventMinOf(req, 5)), false, false))
			p.awaitStatus(hdr.ExchangeID())
			maxInterval, _ := valueUnsigned(valueField(req, 2), 0xFFFF)
			enc := tlv.NewEncoder()
			enc.BeginStructure(tlv.NewAnonymousTag())
			enc.PutUnsigned4(tlv.NewContextTag(0), id)
			enc.PutUnsigned2(tlv.NewContextTag(2), uint16(maxInterval))
			enc.PutUnsigned1(tlv.NewContextTag(interactionModelRevisionTag), interactionModelRevision)
			_ = enc.EndContainer()
			_ = sendIMResponse(p.sess, hdr.ExchangeID(), message.SubscribeResponseMessage, enc.Bytes())
		}
	}
}

// awaitStatus is called on serve's goroutine: it reads until the
// StatusResponse of the exchange arrives.
func (p *eventPublisher) awaitStatus(exchange message.ExchangeID) {
	for {
		raw, err := p.sess.Receive()
		if err != nil {
			return
		}
		hdr, err := message.NewProtocolHeaderFromBytes(raw)
		if err == nil && hdr.Opcode() == message.StatusResponseMessage && hdr.ExchangeID() == exchange {
			return
		}
	}
}

// publish keeps an event and reports it to the subscription on a new
// exchange.
func (p *eventPublisher) publish(id uint32, e testEvent) message.ExchangeID {
	p.mutex.Lock()
	p.events = append(p.events, e)
	p.mutex.Unlock()
	exchange := message.NewFirstExchangeID()
	if err := transmitOnExchange(p.sess, message.ReportDataMessage, exchange, encodeEventReportData(p.t, &id, []testEvent{e}, false, false)); err != nil {
		p.t.Errorf("publish: %v", err)
	}
	return exchange
}

func (p *eventPublisher) nextRequest(t *testing.T) *AttributeValue {
	t.Helper()
	select {
	case r := <-p.requests:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("no request")
		return nil
	}
}

func decodeTestRequest(t *testing.T, body []byte) *AttributeValue {
	t.Helper()
	dec := tlv.NewDecoderWithBytes(body)
	if !dec.Next() {
		t.Fatal("empty request")
	}
	count := 0
	root, err := readValueTree(dec, dec.Element(), 0, &count)
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// eventMinOf returns the EventMin of the request's EventFilters field, 0
// without one.
func eventMinOf(req *AttributeValue, filtersTag uint8) uint64 {
	filters := valueField(req, filtersTag)
	if filters == nil || len(filters.Children) == 0 {
		return 0
	}
	n, _ := valueUnsigned(valueField(filters.Children[0], 1), 1<<64-1)
	return n
}

func positionOf(t *testing.T, e EventReport) uint64 {
	t.Helper()
	if e.Data == nil {
		t.Fatalf("event %d has no data", e.EventNumber)
	}
	n, err := valueUnsigned(valueField(e.Data, 0), 0xFF)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

var keptEvents = []testEvent{
	{number: 1, timestamp: 1_700_000_000_000, position: 1},
	{number: 2, timestamp: 1_700_000_000_500, position: 2},
	{number: 3, timestamp: 1_700_000_001_250, delta: true, position: 1},
}

func TestReadEventsJoinsChunksAndResolvesDeltas(t *testing.T) {
	p, mux := startEventPublisher(t, keptEvents)
	events, err := ReadEvents(mux, []EventRequestPath{NewEventRequestPath(1, 0x003B, 0x01)}, WithReadEventMin(1))
	if err != nil {
		t.Fatalf("ReadEvents() error = %v", err)
	}
	req := p.nextRequest(t)
	paths := valueField(req, 1)
	if paths == nil || len(paths.Children) != 1 || eventMinOf(req, 2) != 1 {
		t.Fatalf("the ReadRequest has event paths %v and EventMin %d", paths, eventMinOf(req, 2))
	}
	if len(events) != 3 {
		t.Fatalf("ReadEvents() = %d events, want 3 from two chunks", len(events))
	}
	for i, e := range events {
		want := keptEvents[i]
		if e.Path != switchPressPath || e.EventNumber != want.number || e.Priority != EventPriorityInfo ||
			e.TimestampType != EventTimestampEpoch || e.Timestamp != want.timestamp || positionOf(t, e) != uint64(want.position) {
			t.Errorf("event %d = %+v, want %+v", i, e, want)
		}
	}
	if at, ok := events[0].Time(); !ok || at.UnixMilli() != int64(keptEvents[0].timestamp) {
		t.Errorf("Time() = %v, %v", at, ok)
	}
}

func TestSubscribeToEvents(t *testing.T) {
	p, mux := startEventPublisher(t, keptEvents[:2])
	reports := make(reportCollector, 8)
	sub, err := mux.Subscribe(context.Background(), nil, reports.handle,
		WithEvents(NewEventRequestPath(1, 0x003B, 0x01)), WithMaxInterval(60*time.Second))
	if err != nil {
		t.Fatalf("Subscribe() error = %v", err)
	}
	defer sub.Close()
	req := p.nextRequest(t)
	if valueField(req, 3) != nil || valueField(req, 4) == nil {
		t.Fatal("the SubscribeRequest has attribute paths, or no event paths")
	}
	priming := reports.next(t)
	if !priming.Priming || len(priming.Events) != 2 || len(priming.Attributes) != 0 {
		t.Fatalf("priming report = %+v, want the 2 kept events", priming)
	}

	exchange := p.publish(sub.ID(), testEvent{number: 3, timestamp: 1_700_000_002_000, position: 1})
	r := reports.next(t)
	if r.Priming || len(r.Events) != 1 || r.Events[0].EventNumber != 3 {
		t.Fatalf("report = %+v, want event 3", r)
	}
	select {
	case got := <-p.statuses:
		if got != exchange {
			t.Fatalf("StatusResponse on exchange %d, want %d", got, exchange)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the report was not answered")
	}
}

func TestResubscribeAsksForTheEventsAfterTheLast(t *testing.T) {
	p, mux := startEventPublisher(t, keptEvents[:2])
	reports := make(reportCollector, 8)
	errs := make(chan error, 8)
	sub, err := mux.Subscribe(context.Background(), nil, reports.handle,
		WithEvents(NewEventRequestPath(1, 0x003B, 0x01)),
		WithMaxInterval(time.Second),
		WithLivenessMargin(300*time.Millisecond),
		WithSubscribeErrorHandler(func(err error) { errs <- err }))
	if err != nil {
		t.Fatalf("Subscribe() error = %v", err)
	}
	defer sub.Close()
	if eventMinOf(p.nextRequest(t), 5) != 0 {
		t.Fatal("the first SubscribeRequest has an EventMin")
	}
	reports.next(t) // priming: events 1 and 2
	p.publish(sub.ID(), testEvent{number: 3, timestamp: 1_700_000_002_000, position: 1})
	reports.next(t)

	// The publisher sends no keep-alive, so the subscription is lost and
	// subscribes again, for the events after 3.
	select {
	case err := <-errs:
		if !errors.Is(err, ErrSubscriptionLost) {
			t.Fatalf("error handler got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the subscription was not lost")
	}
	if got := eventMinOf(p.nextRequest(t), 5); got != 4 {
		t.Fatalf("the resubscription asks for EventMin %d, want 4", got)
	}
	primed := reports.next(t)
	if !primed.Priming || len(primed.Events) != 0 {
		t.Fatalf("resubscription priming = %+v, want no event already reported", primed)
	}
}

func TestEventDeltaTimestampNeedsAnEventBefore(t *testing.T) {
	hdr, err := message.NewProtocolHeader(
		message.WithHeaderExchangeFlags(message.InitiatorFlag|message.ReliabilityFlag),
		message.WithHeaderOpcode(message.ReportDataMessage),
		message.WithHeaderExchangeID(9),
		message.WithHeaderProtocolID(message.InteractionModel),
	).Bytes()
	if err != nil {
		t.Fatal(err)
	}
	raw := append(hdr, encodeEventReportData(t, nil, []testEvent{{number: 1, timestamp: 5, delta: true}}, false, true)...)
	if _, err := decodeReportData(raw); err == nil {
		t.Error("a delta timestamp with no event before it was accepted")
	}
}

func TestSubscribeNeedsAttributeOrEventPaths(t *testing.T) {
	_, mux := startEventPublisher(t, nil)
	if _, err := mux.Subscribe(context.Background(), nil, func(*Report) {}); err == nil {
		t.Error("Subscribe() without attribute or event paths succeeded")
	}
	if _, err := ReadEvents(mux, nil); err == nil {
		t.Error("ReadEvents() without event paths succeeded")
	}
}
