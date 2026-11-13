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
