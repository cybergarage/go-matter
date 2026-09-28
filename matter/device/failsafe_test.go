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

package device

import (
	"sync"
	"testing"
	"time"

	"github.com/cybergarage/go-matter/matter/store"
)

// fakeTimers is a timerFunc whose timers fire only when the test says so.
type fakeTimers struct {
	mutex  sync.Mutex
	now    time.Time
	timers []*fakeTimer
}

type fakeTimer struct {
	at      time.Time
	f       func()
	stopped bool
}

func (ft *fakeTimers) clock() time.Time {
	ft.mutex.Lock()
	defer ft.mutex.Unlock()
	return ft.now
}

func (ft *fakeTimers) start(d time.Duration, f func()) func() bool {
	ft.mutex.Lock()
	defer ft.mutex.Unlock()
	t := &fakeTimer{at: ft.now.Add(d), f: f, stopped: false}
	ft.timers = append(ft.timers, t)
	return func() bool {
		ft.mutex.Lock()
		defer ft.mutex.Unlock()
		was := !t.stopped
		t.stopped = true
		return was
	}
}

// advance moves the clock and fires the timers which are due.
func (ft *fakeTimers) advance(d time.Duration) {
	ft.mutex.Lock()
	ft.now = ft.now.Add(d)
	var due []func()
	for _, t := range ft.timers {
		if !t.stopped && !t.at.After(ft.now) {
			t.stopped = true
			due = append(due, t.f)
		}
	}
	ft.mutex.Unlock()
	for _, f := range due {
		f()
	}
}

func newTestFailSafe(t *testing.T) (*failSafe, *fakeTimers, store.DeviceStore) {
	t.Helper()
	s := store.NewMemDeviceStore()
	ft := &fakeTimers{now: time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)}
	fs := newFailSafe(s)
	fs.now = ft.clock
	fs.timer = ft.start
	return fs, ft, s
}

// stage writes a fabric through the fail-safe's transaction, as AddNOC
// will.
func stage(t *testing.T, fs *failSafe) {
	t.Helper()
	tx := fs.transaction()
	if tx == nil {
		t.Fatal("no transaction while the fail-safe is armed")
	}
	if err := tx.SaveDeviceFabric(store.DeviceFabricRecord{FabricIndex: 1, NodeID: 1}); err != nil {
		t.Fatal(err)
	}
}

func hasFabric(t *testing.T, s store.DeviceStore) bool {
	t.Helper()
	_, ok, err := s.LoadDeviceFabric(1)
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

func TestFailSafeExpiryRollsBack(t *testing.T) {
	fs, ft, s := newTestFailSafe(t)
	expired := false
	fs.onExpire = func() { expired = true }

	if code := fs.arm(0, time.Minute); code != CommissioningOK {
		t.Fatalf("arm() = %d", code)
	}
	stage(t, fs)
	if hasFabric(t, s) {
		t.Fatal("a change is visible before the fail-safe is committed")
	}
	ft.advance(59 * time.Second)
	if !fs.isArmed() {
		t.Fatal("expired before its expiry")
	}
	ft.advance(time.Second)
	if fs.isArmed() || !expired {
		t.Fatalf("after its expiry: armed %v, onExpire called %v", fs.isArmed(), expired)
	}
	if hasFabric(t, s) {
		t.Fatal("the change survived the expiry")
	}
}

func TestFailSafeReArmExtends(t *testing.T) {
	fs, ft, _ := newTestFailSafe(t)
	fs.arm(0, time.Minute)
	ft.advance(50 * time.Second)
	fs.arm(0, time.Minute) // now expires 60s from here
	ft.advance(50 * time.Second)
	if !fs.isArmed() {
		t.Fatal("the first arming's timer disarmed a re-armed fail-safe")
	}
	ft.advance(10 * time.Second)
	if fs.isArmed() {
		t.Fatal("did not expire at the extended expiry")
	}
}

func TestFailSafeCumulativeLimit(t *testing.T) {
	fs, ft, _ := newTestFailSafe(t)
	fs.maxCumulative = 90 * time.Second
	fs.arm(0, time.Minute)
	ft.advance(50 * time.Second)
	fs.arm(0, time.Minute) // capped at 90s from the first arming
	ft.advance(40 * time.Second)
	if fs.isArmed() {
		t.Fatal("stayed armed past the cumulative limit")
	}
}

func TestFailSafeDisarmAndBusy(t *testing.T) {
	fs, _, s := newTestFailSafe(t)
	fs.arm(0, time.Minute)
	stage(t, fs)
	if code := fs.arm(5, time.Minute); code != CommissioningBusyWithOtherAdmin {
		t.Fatalf("arm() by another fabric = %d, want BusyWithOtherAdmin", code)
	}
	if code := fs.arm(0, 0); code != CommissioningOK || fs.isArmed() {
		t.Fatalf("arm(0) = %d, armed %v; want disarmed", code, fs.isArmed())
	}
	if hasFabric(t, s) {
		t.Fatal("the change survived disarming")
	}
	if code := fs.arm(0, 0); code != CommissioningOK {
		t.Fatalf("disarming a disarmed fail-safe = %d, want OK", code)
	}
}

func TestFailSafeCommit(t *testing.T) {
	fs, ft, s := newTestFailSafe(t)
	if code, _ := fs.commit(0); code != CommissioningNoFailSafe {
		t.Fatalf("commit() while disarmed = %d, want NoFailSafe", code)
	}
	fs.arm(0, time.Minute)
	stage(t, fs)
	if code, err := fs.commit(0); code != CommissioningOK || err != nil {
		t.Fatalf("commit() = (%d, %v)", code, err)
	}
	if !hasFabric(t, s) || fs.isArmed() {
		t.Fatalf("after commit: fabric %v, armed %v", hasFabric(t, s), fs.isArmed())
	}
	// The old timer firing later changes nothing.
	ft.advance(2 * time.Minute)
	if !hasFabric(t, s) {
		t.Fatal("a stale timer rolled back a committed change")
	}
}
