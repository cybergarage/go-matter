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
	"sync/atomic"
	"testing"
	"time"

	"github.com/cybergarage/go-matter/matter/encoding/message"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	"github.com/cybergarage/go-matter/matter/protocol/session"
)

var onOffPath = AttributePath{Endpoint: 1, Cluster: 0x0006, Attribute: 0x0000}

// onOffServer serves an On/Off attribute whose value the test sets.
func onOffServer(on *atomic.Bool) *Server {
	srv := NewServer()
	srv.HandleAttribute(onOffPath.Endpoint, onOffPath.Cluster, onOffPath.Attribute, func(enc tlv.Encoder, tag tlv.Tag) Status {
		enc.PutBool(tag, on.Load())
		return StatusSuccess
	})
	return srv
}

// startServerWithClose is startServer whose transport the test closes.
func startServerWithClose(t *testing.T, srv *Server) (SecureSession, func()) {
	t.Helper()
	a2b := make(chan []byte, 16)
	b2a := make(chan []byte, 16)
	closed := make(chan struct{})
	client := session.NewSecureSession(&chanTransport{in: b2a, out: a2b, closed: closed}, serverTestKeys{})
	device := session.NewSecureSession(&chanTransport{in: a2b, out: b2a, closed: closed}, serverTestKeys{}, session.WithRole(session.RoleResponder))
	go func() { _ = srv.Serve(device) }()
	var once sync.Once
	closeFn := func() { once.Do(func() { close(closed) }) }
	t.Cleanup(closeFn)
	return client, closeFn
}

func newTestMux(t *testing.T, sess SecureSession) *ExchangeMux {
	t.Helper()
	mux := NewExchangeMux(sess, WithResponseTimeout(2*time.Second))
	t.Cleanup(func() { _ = mux.Close() })
	return mux
}

// reportCollector is a ReportHandler which hands the reports to the test.
type reportCollector chan *Report

func (c reportCollector) handle(r *Report) { c <- r }

func (c reportCollector) next(t *testing.T) *Report {
	t.Helper()
	select {
	case r := <-c:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("no report")
		return nil
	}
}

func onOffValue(t *testing.T, r *Report) bool {
	t.Helper()
	for _, a := range r.Attributes {
		if a.Path != onOffPath {
			continue
		}
		if a.Value == nil {
			t.Fatalf("OnOff reported with status %+v", a.Status)
		}
		v, ok := a.Value.Element.Bool()
		if !ok {
			t.Fatalf("OnOff is %v, not a boolean", a.Value.Element.Type())
		}
		return v
	}
	t.Fatalf("the report has no OnOff: %+v", r.Attributes)
	return false
}

func subscribeOnOff(t *testing.T, mux *ExchangeMux, reports reportCollector, opts ...SubscribeOption) *Subscription {
	t.Helper()
	sub, err := mux.Subscribe(context.Background(),
		[]AttributeRequestPath{NewAttributeRequestPath(onOffPath.Endpoint, onOffPath.Cluster, onOffPath.Attribute)},
		reports.handle, opts...)
	if err != nil {
		t.Fatalf("Subscribe() error = %v", err)
	}
	t.Cleanup(func() { _ = sub.Close() })
	return sub
}

func TestSubscribeReportsThePrimingValueAndChanges(t *testing.T) {
	var on atomic.Bool
	srv := onOffServer(&on)
	mux := newTestMux(t, startServer(t, srv))
	reports := make(reportCollector, 8)
	sub := subscribeOnOff(t, mux, reports, WithMaxInterval(10*time.Second))

	priming := reports.next(t)
	if !priming.Priming || priming.SubscriptionID != sub.ID() || onOffValue(t, priming) {
		t.Fatalf("priming report = %+v, want OnOff false for subscription %d", priming, sub.ID())
	}
	if sub.MaxInterval() <= 0 || sub.MaxInterval() > 10*time.Second {
		t.Errorf("MaxInterval() = %v, want at most the ceiling asked for", sub.MaxInterval())
	}

	on.Store(true)
	srv.NotifyAttributeChanged(onOffPath)
	change := reports.next(t)
	if change.Priming || !onOffValue(t, change) {
		t.Fatalf("change report = %+v, want OnOff true", change)
	}
}

func TestSubscriptionSharesTheSessionWithRequests(t *testing.T) {
	var on atomic.Bool
	srv := onOffServer(&on)
	toggled := 0
	srv.HandleCommand(onOffPath.Endpoint, onOffPath.Cluster, 0x02, func(*CommandRequest) CommandResult {
		toggled++
		on.Store(!on.Load())
		srv.NotifyAttributeChanged(onOffPath)
		return CommandStatus(StatusSuccess)
	})
	mux := newTestMux(t, startServer(t, srv))
	reports := make(reportCollector, 8)
	subscribeOnOff(t, mux, reports)
	reports.next(t) // priming

	// Toggle, which makes the publisher report on its own exchange while
	// the Invoke waits for its response on this node's.
	resp, err := Invoke(mux, onOffPath.Endpoint, onOffPath.Cluster, 0x02, nil)
	if err != nil || !resp.IsSuccess() {
		t.Fatalf("Invoke(Toggle) = %+v, %v", resp, err)
	}
	if !onOffValue(t, reports.next(t)) {
		t.Fatal("the change report after Toggle has OnOff false")
	}
	v, err := ReadBoolAttribute(mux, onOffPath.Endpoint, onOffPath.Cluster, onOffPath.Attribute)
	if err != nil || !v {
		t.Fatalf("ReadBoolAttribute() = %v, %v; want true", v, err)
	}
}

func TestSubscriptionCloseStopsTheReports(t *testing.T) {
	var on atomic.Bool
	srv := onOffServer(&on)
	mux := newTestMux(t, startServer(t, srv))
	reports := make(reportCollector, 8)
	sub := subscribeOnOff(t, mux, reports)
	reports.next(t) // priming

	if err := sub.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-sub.Done():
	case <-time.After(time.Second):
		t.Fatal("Done() is not closed after Close()")
	}
	if !errors.Is(sub.Err(), ErrSubscriptionClosed) {
		t.Errorf("Err() = %v, want ErrSubscriptionClosed", sub.Err())
	}
	on.Store(true)
	srv.NotifyAttributeChanged(onOffPath)
	select {
	case r := <-reports:
		t.Fatalf("a report arrived after Close(): %+v", r)
	case <-time.After(300 * time.Millisecond):
	}
}

func TestSubscriptionResubscribesWhenLost(t *testing.T) {
	var on atomic.Bool
	srv := onOffServer(&on)
	mux := newTestMux(t, startServer(t, srv))
	reports := make(reportCollector, 8)
	errs := make(chan error, 8)
	sub := subscribeOnOff(t, mux, reports,
		WithMaxInterval(time.Second),
		WithLivenessMargin(300*time.Millisecond),
		WithSubscribeErrorHandler(func(err error) { errs <- err }))
	reports.next(t) // priming
	first := sub.ID()

	// The publisher drops the subscription without a word.
	srv.endSubscription(first)

	select {
	case err := <-errs:
		if !errors.Is(err, ErrSubscriptionLost) {
			t.Fatalf("error handler got %v, want ErrSubscriptionLost", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the lost subscription was not reported")
	}
	primed := reports.next(t)
	if !primed.Priming || sub.ID() == first || primed.SubscriptionID != sub.ID() {
		t.Fatalf("after resubscribing: report %+v, ID %d (was %d); want a priming report of a new ID", primed, sub.ID(), first)
	}
	on.Store(true)
	srv.NotifyAttributeChanged(onOffPath)
	if !onOffValue(t, reports.next(t)) {
		t.Fatal("the resubscribed subscription did not report the change")
	}
}

func TestSubscriptionEndsWhenTheSessionFails(t *testing.T) {
	var on atomic.Bool
	sess, closeTransport := startServerWithClose(t, onOffServer(&on))
	mux := newTestMux(t, sess)
	reports := make(reportCollector, 8)
	errs := make(chan error, 8)
	sub := subscribeOnOff(t, mux, reports, WithSubscribeErrorHandler(func(err error) { errs <- err }))
	reports.next(t) // priming

	closeTransport()
	select {
	case <-sub.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the subscription did not end with its session")
	}
	if sub.Err() == nil || errors.Is(sub.Err(), ErrSubscriptionClosed) {
		t.Errorf("Err() = %v, want the session's failure", sub.Err())
	}
	select {
	case <-errs:
	case <-time.After(time.Second):
		t.Error("the error handler was not told")
	}
	if _, err := ReadBoolAttribute(mux, onOffPath.Endpoint, onOffPath.Cluster, onOffPath.Attribute); err == nil {
		t.Error("ReadBoolAttribute() on a failed session succeeded")
	}
}

func TestSubscribeRejectsInvalidArguments(t *testing.T) {
	var on atomic.Bool
	mux := newTestMux(t, startServer(t, onOffServer(&on)))
	path := []AttributeRequestPath{NewAttributeRequestPath(1, 6, 0)}
	if _, err := mux.Subscribe(context.Background(), nil, func(*Report) {}); err == nil {
		t.Error("Subscribe() without paths succeeded")
	}
	if _, err := mux.Subscribe(context.Background(), path, nil); err == nil {
		t.Error("Subscribe() without a handler succeeded")
	}
	if _, err := mux.Subscribe(context.Background(), path, func(*Report) {}, WithMinInterval(10*time.Second), WithMaxInterval(time.Second)); err == nil {
		t.Error("Subscribe() with min > max succeeded")
	}
}

// encodeTestReportData encodes a ReportData chunk of OnOff list items.
func encodeTestReportData(t *testing.T, id uint32, more bool, items []uint16, appendItems bool) []byte {
	t.Helper()
	hdr, err := message.NewProtocolHeader(
		message.WithHeaderExchangeFlags(message.InitiatorFlag|message.ReliabilityFlag),
		message.WithHeaderOpcode(message.ReportDataMessage),
		message.WithHeaderExchangeID(7),
		message.WithHeaderProtocolID(message.InteractionModel),
	).Bytes()
	if err != nil {
		t.Fatal(err)
	}
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	enc.PutUnsigned4(tlv.NewContextTag(0), id)
	enc.BeginArray(tlv.NewContextTag(1))
	putPath := func(appendItem bool) {
		enc.BeginList(tlv.NewContextTag(1))
		enc.PutUnsigned2(tlv.NewContextTag(2), 1)
		_ = enc.PutUnsigned(tlv.NewContextTag(3), 0x001D)
		_ = enc.PutUnsigned(tlv.NewContextTag(4), 0x0003)
		if appendItem {
			enc.PutNull(tlv.NewContextTag(5))
		}
		_ = enc.EndContainer()
	}
	if !appendItems {
		enc.BeginStructure(tlv.NewAnonymousTag())
		enc.BeginStructure(tlv.NewContextTag(1))
		enc.PutUnsigned4(tlv.NewContextTag(0), 9)
		putPath(false)
		enc.BeginArray(tlv.NewContextTag(2))
		for _, v := range items {
			enc.PutUnsigned2(tlv.NewAnonymousTag(), v)
		}
		_ = enc.EndContainer()
		_ = enc.EndContainer()
		_ = enc.EndContainer()
	} else {
		for _, v := range items {
			enc.BeginStructure(tlv.NewAnonymousTag())
			enc.BeginStructure(tlv.NewContextTag(1))
			enc.PutUnsigned4(tlv.NewContextTag(0), 9)
			putPath(true)
			enc.PutUnsigned2(tlv.NewContextTag(2), v)
			_ = enc.EndContainer()
			_ = enc.EndContainer()
		}
	}
	_ = enc.EndContainer()
	enc.PutBool(tlv.NewContextTag(3), more)
	enc.PutUnsigned1(tlv.NewContextTag(interactionModelRevisionTag), interactionModelRevision)
	_ = enc.EndContainer()
	return append(hdr, enc.Bytes()...)
}

func TestReportChunksJoinListItems(t *testing.T) {
	first, err := decodeReportData(encodeTestReportData(t, 42, true, []uint16{1, 2}, false))
	if err != nil {
		t.Fatal(err)
	}
	second, err := decodeReportData(encodeTestReportData(t, 42, false, []uint16{3, 4}, true))
	if err != nil {
		t.Fatal(err)
	}
	if first.subscriptionID != 42 || !first.moreChunks || second.moreChunks {
		t.Fatalf("chunks = %+v, %+v", first, second)
	}
	reports := mergeAttributeReports(nil, first.attributes)
	reports = mergeAttributeReports(reports, second.attributes)
	if len(reports) != 1 {
		t.Fatalf("%d attribute reports, want the list once", len(reports))
	}
	r := reports[0]
	if r.Path != (AttributePath{Endpoint: 1, Cluster: 0x001D, Attribute: 0x0003}) || !r.HasDataVersion || r.DataVersion != 9 {
		t.Fatalf("report = %+v", r)
	}
	var got []uint64
	for _, c := range r.Value.Children {
		v, _ := c.Element.Unsigned()
		got = append(got, v)
	}
	if len(got) != 4 || got[0] != 1 || got[3] != 4 {
		t.Fatalf("list = %v, want [1 2 3 4]", got)
	}
}
