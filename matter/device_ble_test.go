// Copyright (C) 2026 The go-matter Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package matter

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/cybergarage/go-matter/matter/ble"
	"github.com/cybergarage/go-matter/matter/ble/btp"
)

// hangingBLEDevice is a BLE device whose first connection attempts get no
// answer: they last until their context ends, as a connection request to
// a device out of range does.
type hangingBLEDevice struct {
	ble.Device

	mu        sync.Mutex
	hangs     int
	attempts  int
	deadlines []bool
}

func (d *hangingBLEDevice) Connect(ctx context.Context) error {
	d.mu.Lock()
	d.attempts++
	_, hasDeadline := ctx.Deadline()
	d.deadlines = append(d.deadlines, hasDeadline)
	hang := d.attempts <= d.hangs
	d.mu.Unlock()
	if !hang {
		return nil
	}
	<-ctx.Done()
	return ctx.Err()
}

func (d *hangingBLEDevice) Disconnect() error { return nil }

func withAttemptTimeout(t *testing.T, timeout time.Duration) {
	t.Helper()
	saved := bleConnectAttemptTimeout
	bleConnectAttemptTimeout = timeout
	t.Cleanup(func() { bleConnectAttemptTimeout = saved })
}

// An attempt which gets no answer ends after its own timeout, and the next
// attempt is made, instead of the first one using up the caller's time.
func TestConnectWithRetryBoundsEachAttempt(t *testing.T) {
	withAttemptTimeout(t, 50*time.Millisecond)
	payload := testPairingCode(t)
	hanging := &hangingBLEDevice{hangs: 1}
	dev := newBLEDevice(hanging, &matchingBLEService{payload: payload}, &stubDiscoverer{}).(*bleDevice)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := dev.connectWithRetry(ctx); err != nil {
		t.Fatalf("connectWithRetry() error = %v", err)
	}
	hanging.mu.Lock()
	defer hanging.mu.Unlock()
	if hanging.attempts != 2 {
		t.Fatalf("attempts = %d, want 2", hanging.attempts)
	}
	for i, ok := range hanging.deadlines {
		if !ok {
			t.Errorf("attempt %d had no deadline", i+1)
		}
	}
}

// When every attempt gets no answer, the error says so after all of them.
func TestConnectWithRetryGivesUp(t *testing.T) {
	withAttemptTimeout(t, 20*time.Millisecond)
	payload := testPairingCode(t)
	hanging := &hangingBLEDevice{hangs: bleConnectAttempts}
	dev := newBLEDevice(hanging, &matchingBLEService{payload: payload}, &stubDiscoverer{}).(*bleDevice)

	err := dev.connectWithRetry(context.Background())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("connectWithRetry() error = %v", err)
	}
	if hanging.attempts != bleConnectAttempts {
		t.Fatalf("attempts = %d, want %d", hanging.attempts, bleConnectAttempts)
	}
}

// recordingTransport is a BLE transport which delivers one message, and
// records the deadline of the context each read was given.
type recordingTransport struct {
	ble.Transport

	segments  [][]byte
	deadlines []time.Time
	block     bool
}

func (tr *recordingTransport) Read(ctx context.Context) ([]byte, error) {
	deadline, _ := ctx.Deadline()
	tr.deadlines = append(tr.deadlines, deadline)
	if tr.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	seg := tr.segments[0]
	tr.segments = tr.segments[1:]
	return seg, nil
}

func receivingDevice(t *testing.T, tr *recordingTransport) *bleDevice {
	t.Helper()
	dev := newBLEDevice(&hangingBLEDevice{}, &matchingBLEService{payload: testPairingCode(t)}, &stubDiscoverer{}).(*bleDevice)
	dev.transport = tr
	dev.segmenter = btp.NewSegmenter(64)
	// The peer's first data segment after the handshake is number 1.
	peer := btp.NewSegmenter(64)
	peer.EncodeMessage(nil)
	tr.segments = peer.EncodeMessage([]byte("response"))
	return dev
}

// A secure session receives with a context without a deadline, and go-ble
// then gives up after 5 seconds. During a commissioning, such a receive
// waits as long as the commissioning instead: a device answers
// ConnectNetwork only once it has joined the network (11.8.6.4).
func TestBLEReceiveIsBoundedByTheCommissioning(t *testing.T) {
	commissioning, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	want, _ := commissioning.Deadline()

	cancellable, cancelCaller := context.WithCancel(context.Background())
	defer cancelCaller()
	own, cancelOwn := context.WithTimeout(context.Background(), time.Second)
	defer cancelOwn()
	ownDeadline, _ := own.Deadline()

	for name, tc := range map[string]struct {
		ctx  context.Context
		want time.Time
	}{
		"background":  {context.Background(), want},
		"cancellable": {cancellable, want},
		"own":         {own, ownDeadline},
	} {
		tr := &recordingTransport{}
		dev := receivingDevice(t, tr)
		dev.commissioning = commissioning
		msg, err := dev.Receive(tc.ctx)
		if err != nil || string(msg) != "response" {
			t.Fatalf("%s: Receive() = %q, %v", name, msg, err)
		}
		if len(tr.deadlines) != 1 || !tr.deadlines[0].Equal(tc.want) {
			t.Errorf("%s: read deadline = %v, want %v", name, tr.deadlines, tc.want)
		}
	}

	// Outside a commissioning the context is passed on as it is.
	tr := &recordingTransport{}
	if _, err := receivingDevice(t, tr).Receive(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !tr.deadlines[0].IsZero() {
		t.Errorf("read deadline outside a commissioning = %v, want none", tr.deadlines[0])
	}
}

// A commissioning which ends, by its deadline or cancelled, ends a receive
// the caller could still cancel itself.
func TestBLEReceiveEndsWithTheCommissioning(t *testing.T) {
	commissioning, cancel := context.WithCancel(context.Background())
	tr := &recordingTransport{block: true}
	dev := receivingDevice(t, tr)
	dev.commissioning = commissioning

	caller, cancelCaller := context.WithCancel(context.Background())
	defer cancelCaller()
	done := make(chan error, 1)
	go func() {
		_, err := dev.Receive(caller)
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Receive() error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Receive() did not end with the commissioning")
	}
}
