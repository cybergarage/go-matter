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
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cybergarage/go-matter/matter/protocol/pase"
	"github.com/cybergarage/go-matter/matter/store"
	"github.com/cybergarage/go-matter/matter/types"
)

// withFakeTimers makes the device's commissioning window and fail-safe run
// on ft.
func withFakeTimers(ft *fakeTimers) Option {
	return func(d *Device) error {
		d.now = ft.clock
		d.timer = ft.start
		return nil
	}
}

func newFakeTimers() *fakeTimers {
	return &fakeTimers{now: time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)}
}

// tryPASE runs PASE with the device and reports whether it was
// established. A device which refuses PASE does not answer, so the attempt
// gives up soon.
func tryPASE(t *testing.T, d *Device, passcode types.Passcode) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	_, err := pase.NewInitiator(dialDevice(t, d), passcode).EstablishSession(ctx)
	return err
}

// waitFor polls cond until it holds.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (d *Device) commissionerSession() *Session {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.window.commissioner
}

func (d *Device) failedAttempts() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.window.failures
}

// TestCommissioningWindowDuringPASE checks that a PASE session takes the
// window: the device stops advertising, arms the fail-safe and refuses
// other commissioners, and when the fail-safe expires it closes the
// session, counts a failed attempt and advertises again.
func TestCommissioningWindowDuringPASE(t *testing.T) {
	ft := newFakeTimers()
	d, adv, _ := startTestDevice(t, withFakeTimers(ft))
	if !d.IsCommissioningWindowOpen() || !adv.isCommissionable() {
		t.Fatal("a device without fabrics did not open its commissioning window at Start")
	}

	if err := tryPASE(t, d, testPasscode); err != nil {
		t.Fatal(err)
	}
	if !d.failSafe.isArmed() {
		t.Fatal("the fail-safe is not armed once PASE is established")
	}
	if d.commissionerSession() == nil {
		t.Fatal("the PASE session is not the commissioning in progress")
	}
	if adv.isCommissionable() {
		t.Fatal("the device still advertises while commissioning is in progress")
	}
	if err := tryPASE(t, d, testPasscode); err == nil {
		t.Fatal("a second commissioner established PASE while commissioning was in progress")
	}

	// The commissioner goes away; the fail-safe expires.
	ft.advance(PASEFailSafeExpiry)
	if d.commissionerSession() != nil {
		t.Fatal("the PASE session outlived the fail-safe")
	}
	if n := d.failedAttempts(); n != 1 {
		t.Fatalf("%d failed attempts after the fail-safe expired, want 1", n)
	}
	if !d.IsCommissioningWindowOpen() || !adv.isCommissionable() {
		t.Fatal("the device does not advertise again after a failed attempt")
	}
	if err := tryPASE(t, d, testPasscode); err != nil {
		t.Fatalf("PASE after a failed attempt: %v", err)
	}
}

// TestCommissioningWindowClosesAfterFailedAttempts checks that the window
// closes after MaxFailedCommissioningAttempts failed attempts.
func TestCommissioningWindowClosesAfterFailedAttempts(t *testing.T) {
	d, adv, _ := startTestDevice(t)
	d.mu.Lock()
	for range MaxFailedCommissioningAttempts - 1 {
		d.failedAttemptLocked("test")
	}
	d.mu.Unlock()
	if !d.IsCommissioningWindowOpen() {
		t.Fatalf("the window closed after %d failed attempts", MaxFailedCommissioningAttempts-1)
	}

	if err := tryPASE(t, d, types.Passcode(20202020)); err == nil {
		t.Fatal("PASE with a wrong passcode succeeded")
	}
	waitFor(t, "the window to close", func() bool { return !d.IsCommissioningWindowOpen() })
	if adv.isCommissionable() {
		t.Fatal("the device advertises with its window closed")
	}
	if err := tryPASE(t, d, testPasscode); err == nil {
		t.Fatal("PASE succeeded with the window closed")
	}
}

// TestCommissioningWindowTimeoutAndReopen checks the window's timeout and
// OpenCommissioningWindow.
func TestCommissioningWindowTimeoutAndReopen(t *testing.T) {
	ft := newFakeTimers()
	d, adv, _ := startTestDevice(t, withFakeTimers(ft), WithCommissioningTimeout(5*time.Minute))
	ft.advance(5*time.Minute - time.Second)
	if !d.IsCommissioningWindowOpen() {
		t.Fatal("the window closed before its timeout")
	}
	ft.advance(time.Second)
	if d.IsCommissioningWindowOpen() || adv.isCommissionable() {
		t.Fatal("the window is still open after its timeout")
	}

	if err := d.OpenCommissioningWindow(time.Minute); err == nil {
		t.Fatal("OpenCommissioningWindow accepted a timeout below the minimum")
	}
	before := d.CommissionableService().InstanceName
	if err := d.OpenCommissioningWindow(MinCommissioningTimeout); err != nil {
		t.Fatal(err)
	}
	if !d.IsCommissioningWindowOpen() || !adv.isCommissionable() {
		t.Fatal("OpenCommissioningWindow did not advertise")
	}
	if d.CommissionableService().InstanceName == before {
		t.Fatal("the reopened window kept the previous instance name")
	}
	if err := d.OpenCommissioningWindow(MinCommissioningTimeout); !errors.Is(err, ErrCommissioningWindowOpen) {
		t.Fatalf("OpenCommissioningWindow on an open window: %v", err)
	}
	if err := d.CloseCommissioningWindow(); err != nil {
		t.Fatal(err)
	}
	if d.IsCommissioningWindowOpen() || adv.isCommissionable() {
		t.Fatal("CloseCommissioningWindow left the window open")
	}
	if _, err := New(WithPasscode(testPasscode), WithCommissioningTimeout(time.Minute)); err == nil {
		t.Fatal("WithCommissioningTimeout accepted a timeout below the minimum")
	}
}

// TestCommissionedDeviceStartsClosed checks that a device already on a
// fabric does not open its window at Start.
func TestCommissionedDeviceStartsClosed(t *testing.T) {
	s := store.NewMemDeviceStore()
	if err := s.SaveDeviceFabric(store.DeviceFabricRecord{FabricIndex: 1, FabricID: 1, NodeID: 1}); err != nil {
		t.Fatal(err)
	}
	d, adv, _ := startTestDevice(t, WithDeviceStore(s))
	if d.IsCommissioningWindowOpen() || adv.isCommissionable() {
		t.Fatal("a commissioned device opened its commissioning window at Start")
	}
	if err := tryPASE(t, d, testPasscode); err == nil {
		t.Fatal("a commissioned device accepted PASE with its window closed")
	}
}
