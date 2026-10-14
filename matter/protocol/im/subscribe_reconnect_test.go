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
	"testing"
	"time"

	"github.com/cybergarage/go-matter/matter/protocol/session"
)

// testReconnector reconnects to a server with a new session, once per
// failed mux, the way a node does.
type testReconnector struct {
	t     *testing.T
	srv   *Server
	mutex sync.Mutex
	mux   *ExchangeMux
	calls atomic.Int32
	// closed makes the reconnections fail as for a closed node.
	closed atomic.Bool
}

func (r *testReconnector) current() *ExchangeMux {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.mux
}

func (r *testReconnector) reconnect(_ context.Context, failed *ExchangeMux) (*ExchangeMux, error) {
	if r.closed.Load() {
		return nil, fmt.Errorf("test node closed: %w", ErrSubscriptionClosed)
	}
	r.mutex.Lock()
	defer r.mutex.Unlock()
	if r.mux != failed {
		return r.mux, nil
	}
	r.calls.Add(1)
	r.mux = newTestMux(r.t, startServer(r.t, r.srv))
	return r.mux, nil
}

// deafTransport drops what it transmits once deaf, as a publisher which
// forgot the session does.
type deafTransport struct {
	*chanTransport
	deaf *atomic.Bool
}

func (d *deafTransport) Transmit(ctx context.Context, b []byte) error {
	if d.deaf.Load() {
		return nil
	}
	return d.chanTransport.Transmit(ctx, b)
}

func startDeafableServer(t *testing.T, srv *Server, deaf *atomic.Bool) SecureSession {
	t.Helper()
	a2b := make(chan []byte, 16)
	b2a := make(chan []byte, 16)
	closed := make(chan struct{})
	client := session.NewSecureSession(&deafTransport{chanTransport: &chanTransport{in: b2a, out: a2b, closed: closed}, deaf: deaf}, serverTestKeys{})
	device := session.NewSecureSession(&chanTransport{in: a2b, out: b2a, closed: closed}, serverTestKeys{}, session.WithRole(session.RoleResponder))
	go func() { _ = srv.Serve(device) }()
	t.Cleanup(func() { close(closed) })
	return client
}

func TestSubscriptionsMoveToTheReconnectedSession(t *testing.T) {
	var on atomic.Bool
	srv := onOffServer(&on)
	sess, closeTransport := startServerWithClose(t, srv)
	r := &testReconnector{t: t, srv: srv, mux: newTestMux(t, sess)}
	first := r.current()

	reports := []reportCollector{make(reportCollector, 8), make(reportCollector, 8)}
	subs := make([]*Subscription, len(reports))
	for i := range reports {
		subs[i] = subscribeOnOff(t, first, reports[i], WithReconnect(r.reconnect))
		reports[i].next(t) // priming
	}

	closeTransport()
	for i, sub := range subs {
		primed := reports[i].next(t)
		if !primed.Priming || onOffValue(t, primed) {
			t.Fatalf("subscription %d after the reconnection: %+v, want a priming report of OnOff false", i, primed)
		}
		if sub.currentMux() != r.current() {
			t.Fatalf("subscription %d is not on the new session", i)
		}
	}
	if n := r.calls.Load(); n != 1 {
		t.Errorf("reconnected %d times, want once for the both subscriptions", n)
	}
	on.Store(true)
	srv.NotifyAttributeChanged(onOffPath)
	for i := range subs {
		if !onOffValue(t, reports[i].next(t)) {
			t.Fatalf("subscription %d did not report the change over the new session", i)
		}
	}
}

func TestSubscriptionReconnectsWhenThePublisherStopsAnswering(t *testing.T) {
	var on atomic.Bool
	var deaf atomic.Bool
	srv := onOffServer(&on)
	r := &testReconnector{t: t, srv: srv, mux: newTestMux(t, startDeafableServer(t, srv, &deaf))}
	reports := make(reportCollector, 8)
	sub := subscribeOnOff(t, r.current(), reports,
		WithReconnect(r.reconnect),
		WithMaxInterval(time.Second),
		WithLivenessMargin(300*time.Millisecond))
	reports.next(t) // priming
	first := sub.ID()

	// The publisher restarts: it forgets the subscription and the session.
	deaf.Store(true)
	srv.endSubscription(first)

	select {
	case primed := <-reports:
		if !primed.Priming {
			t.Fatalf("report %+v, want a priming one", primed)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the subscription did not reconnect")
	}
	if r.calls.Load() != 1 || sub.currentMux() != r.current() {
		t.Fatal("the subscription is not on a reconnected session")
	}
}

func TestSubscriptionEndsWhenTheNodeIsClosed(t *testing.T) {
	var on atomic.Bool
	srv := onOffServer(&on)
	sess, closeTransport := startServerWithClose(t, srv)
	r := &testReconnector{t: t, srv: srv, mux: newTestMux(t, sess)}
	reports := make(reportCollector, 8)
	errs := make(chan error, 8)
	sub := subscribeOnOff(t, r.current(), reports, WithReconnect(r.reconnect),
		WithSubscribeErrorHandler(func(err error) { errs <- err }))
	reports.next(t) // priming

	r.closed.Store(true)
	closeTransport()
	select {
	case <-sub.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the subscription did not end")
	}
	if !errors.Is(sub.Err(), ErrSubscriptionClosed) {
		t.Errorf("Err() = %v, want ErrSubscriptionClosed", sub.Err())
	}
}
