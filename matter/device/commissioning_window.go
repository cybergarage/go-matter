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
	"errors"
	"fmt"
	"time"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter/mdns"
	"github.com/cybergarage/go-matter/matter/protocol/pase"
)

// Commissioning window limits (Matter Core 5.4.2.3, 11.19.8.1).
const (
	// MinCommissioningTimeout and MaxCommissioningTimeout bound a window
	// OpenCommissioningWindow opens.
	MinCommissioningTimeout = 3 * time.Minute
	MaxCommissioningTimeout = 15 * time.Minute
	// DefaultCommissioningTimeout is how long the window a device without
	// fabrics opens at Start stays open, unless WithCommissioningTimeout
	// says otherwise; MaxInitialCommissioningTimeout is the longest it can
	// be, an uncommissioned device's extended announcement.
	DefaultCommissioningTimeout    = 15 * time.Minute
	MaxInitialCommissioningTimeout = 48 * time.Hour
	// MaxFailedCommissioningAttempts is how many failed attempts close the
	// window, whether PASE failed or the fail-safe expired after it
	// (5.4.2.3).
	MaxFailedCommissioningAttempts = 20
	// PASEFailSafeExpiry is how long the fail-safe a device arms when a
	// PASE session is established lasts (11.10.6.2.1).
	PASEFailSafeExpiry = 60 * time.Second
)

var (
	// ErrCommissioningWindowOpen is returned by OpenCommissioningWindow
	// when the window is already open.
	ErrCommissioningWindowOpen = errors.New("device: the commissioning window is already open")
	// ErrNotStarted is returned by OpenCommissioningWindow before Start.
	ErrNotStarted = errors.New("device: not started")
)

// WithCommissioningTimeout sets how long the commissioning window a device
// without fabrics opens at Start stays open: DefaultCommissioningTimeout
// by default, and between MinCommissioningTimeout and
// MaxInitialCommissioningTimeout.
func WithCommissioningTimeout(timeout time.Duration) Option {
	return func(d *Device) error {
		if timeout < MinCommissioningTimeout || MaxInitialCommissioningTimeout < timeout {
			return fmt.Errorf("device: commissioning timeout %v is outside %v..%v", timeout, MinCommissioningTimeout, MaxInitialCommissioningTimeout)
		}
		d.initialWindowTimeout = timeout
		return nil
	}
}

// commissioningWindow is the state of the device's commissioning window
// (Matter Core 5.4.2.3), guarded by the device's lock: while it is open the
// device advertises _matterc._udp and accepts PASE, and it closes when
// commissioning completes, when it times out, or after
// MaxFailedCommissioningAttempts failed attempts.
type commissioningWindow struct {
	open       bool
	opening    windowOpening
	stop       func() bool
	generation int
	failures   int
	// commissioner is the PASE session commissioning is in progress on;
	// while there is one, the device neither advertises nor accepts
	// another PASE.
	commissioner *Session
}

// WindowStatus is how the commissioning window is open, the
// Administrator Commissioning cluster's CommissioningWindowStatusEnum
// (Matter Core 11.19.5.1).
type WindowStatus uint8

const (
	WindowNotOpen      WindowStatus = 0
	EnhancedWindowOpen WindowStatus = 1
	BasicWindowOpen    WindowStatus = 2
)

// windowOpening is how a commissioning window was opened: with the
// device's own verifier and discriminator (basic), or with those an
// administrator gave (enhanced), and by which administrator.
type windowOpening struct {
	status        WindowStatus
	verifier      *pase.Verifier
	discriminator uint16
	// adminFabric and adminVendor identify the administrator which opened
	// the window; 0 when the device opened it.
	adminFabric uint8
	adminVendor uint16
}

// IsCommissioningWindowOpen reports whether the device can be
// commissioned: it advertises itself as commissionable and accepts PASE.
func (d *Device) IsCommissioningWindowOpen() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.window.open
}

// OpenCommissioningWindow opens the commissioning window for timeout,
// between MinCommissioningTimeout and MaxCommissioningTimeout, with the
// device's passcode, as an administrator does to add another fabric
// (11.19.8.1). The device advertises under a new instance name.
func (d *Device) OpenCommissioningWindow(timeout time.Duration) error {
	if timeout < MinCommissioningTimeout || MaxCommissioningTimeout < timeout {
		return fmt.Errorf("device: commissioning timeout %v is outside %v..%v", timeout, MinCommissioningTimeout, MaxCommissioningTimeout)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.conn == nil {
		return ErrNotStarted
	}
	if d.window.open {
		return ErrCommissioningWindowOpen
	}
	d.service.InstanceName = NewInstanceName()
	return d.openWindowLocked(timeout, d.basicOpeningLocked(0, 0))
}

// OpenEnhancedCommissioningWindow opens the commissioning window for
// timeout, as OpenCommissioningWindow does, but with the PASE verifier and
// the discriminator an administrator generated, so that it hands out a
// one-time passcode instead of the device's own (11.19.8.1). The device
// advertises the window with CM=2.
func (d *Device) OpenEnhancedCommissioningWindow(timeout time.Duration, verifier pase.Verifier, discriminator uint16) error {
	return d.openEnhancedWindow(timeout, verifier, discriminator, 0, 0)
}

func (d *Device) openEnhancedWindow(timeout time.Duration, verifier pase.Verifier, discriminator uint16, adminFabric uint8, adminVendor uint16) error {
	if timeout < MinCommissioningTimeout || MaxCommissioningTimeout < timeout {
		return fmt.Errorf("device: commissioning timeout %v is outside %v..%v", timeout, MinCommissioningTimeout, MaxCommissioningTimeout)
	}
	if err := verifier.Validate(); err != nil {
		return err
	}
	if MaxDiscriminator < discriminator {
		return fmt.Errorf("device: discriminator 0x%X exceeds 12 bits", discriminator)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.conn == nil {
		return ErrNotStarted
	}
	if d.window.open {
		return ErrCommissioningWindowOpen
	}
	d.service.InstanceName = NewInstanceName()
	return d.openWindowLocked(timeout, windowOpening{
		status:        EnhancedWindowOpen,
		verifier:      &verifier,
		discriminator: discriminator,
		adminFabric:   adminFabric,
		adminVendor:   adminVendor,
	})
}

// openBasicWindow opens the window with the device's own verifier on
// behalf of an administrator.
func (d *Device) openBasicWindow(timeout time.Duration, adminFabric uint8, adminVendor uint16) error {
	if timeout < MinCommissioningTimeout || MaxCommissioningTimeout < timeout {
		return fmt.Errorf("device: commissioning timeout %v is outside %v..%v", timeout, MinCommissioningTimeout, MaxCommissioningTimeout)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.conn == nil {
		return ErrNotStarted
	}
	if d.window.open {
		return ErrCommissioningWindowOpen
	}
	d.service.InstanceName = NewInstanceName()
	return d.openWindowLocked(timeout, d.basicOpeningLocked(adminFabric, adminVendor))
}

func (d *Device) basicOpeningLocked(adminFabric uint8, adminVendor uint16) windowOpening {
	return windowOpening{
		status:        BasicWindowOpen,
		verifier:      nil,
		discriminator: d.discriminator,
		adminFabric:   adminFabric,
		adminVendor:   adminVendor,
	}
}

// windowState returns how the window is open, and by which administrator.
func (d *Device) windowState() windowOpening {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.window.open {
		return windowOpening{status: WindowNotOpen, verifier: nil, discriminator: 0, adminFabric: 0, adminVendor: 0}
	}
	return d.window.opening
}

// paseVerifierLocked returns the verifier PASE authenticates with: the
// one an enhanced window was opened with, or the device's own.
func (d *Device) paseVerifierLocked() pase.Verifier {
	if d.window.opening.verifier != nil {
		return *d.window.opening.verifier
	}
	return d.verifier
}

// CloseCommissioningWindow closes the commissioning window, as
// RevokeCommissioning does (11.19.8.3). A commissioning already in
// progress is not interrupted.
func (d *Device) CloseCommissioningWindow() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.closeWindowLocked("closed")
}

// revokeCommissioning closes the window and ends a commissioning in
// progress: its PASE session is closed, and the fail-safe rolled back
// (11.19.8.3).
func (d *Device) revokeCommissioning() {
	d.mu.Lock()
	if err := d.closeWindowLocked("revoked"); err != nil {
		log.Warnf("device: %v", err)
	}
	if sess := d.window.commissioner; sess != nil {
		d.closeSessionLocked(sess)
	}
	d.mu.Unlock()
	// Not under the device's lock: a rollback calls back into it.
	d.failSafe.close()
}

func (d *Device) openWindowLocked(timeout time.Duration, opening windowOpening) error {
	d.window.open = true
	d.window.opening = opening
	d.service.Discriminator = opening.discriminator
	d.window.failures = 0
	d.window.generation++
	gen := d.window.generation
	d.window.stop = d.timer(timeout, func() { d.windowTimedOut(gen) })
	if d.window.commissioner != nil {
		return nil
	}
	if err := d.advertiseCommissionableLocked(); err != nil {
		d.stopWindowTimerLocked()
		d.window.open = false
		d.window.opening = windowOpening{status: WindowNotOpen, verifier: nil, discriminator: 0, adminFabric: 0, adminVendor: 0}
		d.service.Discriminator = d.discriminator
		return err
	}
	log.Infof("device: commissioning window open for %v", timeout)
	return nil
}

func (d *Device) closeWindowLocked(reason string) error {
	if !d.window.open {
		return nil
	}
	d.window.open = false
	d.window.opening = windowOpening{status: WindowNotOpen, verifier: nil, discriminator: 0, adminFabric: 0, adminVendor: 0}
	d.service.Discriminator = d.discriminator
	d.stopWindowTimerLocked()
	log.Infof("device: commissioning window %s", reason)
	if d.advertiser == nil {
		return nil
	}
	return d.advertiser.WithdrawCommissionable()
}

func (d *Device) stopWindowTimerLocked() {
	if d.window.stop != nil {
		d.window.stop()
		d.window.stop = nil
	}
	d.window.generation++
}

func (d *Device) advertiseCommissionableLocked() error {
	if d.advertiser == nil {
		return nil
	}
	d.service.CommissioningMode = mdns.CommissioningModePasscode
	if d.window.opening.status == EnhancedWindowOpen {
		d.service.CommissioningMode = mdns.CommissioningModeDynamicPasscode
	}
	if err := d.advertiser.AdvertiseCommissionable(d.service); err != nil {
		return fmt.Errorf("device: advertise: %w", err)
	}
	return nil
}

func (d *Device) windowTimedOut(gen int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if gen != d.window.generation {
		return
	}
	if err := d.closeWindowLocked("timed out"); err != nil {
		log.Warnf("device: %v", err)
	}
}

// acceptsPASELocked reports whether a PBKDFParamRequest may start PASE:
// the window is open and no commissioning is in progress.
func (d *Device) acceptsPASELocked() bool {
	return d.window.open && d.window.commissioner == nil
}

// commissioningStartedLocked records the PASE session commissioning goes
// on over; the device stops advertising until it ends.
func (d *Device) commissioningStartedLocked(sess *Session) {
	d.window.commissioner = sess
	if d.advertiser == nil {
		return
	}
	if err := d.advertiser.WithdrawCommissionable(); err != nil {
		log.Warnf("device: withdraw the commissionable service: %v", err)
	}
}

// failedAttemptLocked counts a failed commissioning attempt: the window
// closes after MaxFailedCommissioningAttempts of them, and until then the
// device advertises again for the next attempt.
func (d *Device) failedAttemptLocked(reason string) {
	if !d.window.open {
		return
	}
	d.window.failures++
	log.Infof("device: commissioning attempt %d failed: %s", d.window.failures, reason)
	if MaxFailedCommissioningAttempts <= d.window.failures {
		if err := d.closeWindowLocked(fmt.Sprintf("closed after %d failed attempts", d.window.failures)); err != nil {
			log.Warnf("device: %v", err)
		}
		return
	}
	if d.window.commissioner == nil {
		if err := d.advertiseCommissionableLocked(); err != nil {
			log.Warnf("device: %v", err)
		}
	}
}

// failSafeExpired ends the commissioning the expired fail-safe guarded:
// its PASE session is closed, and the attempt counts as failed.
func (d *Device) failSafeExpired() {
	d.mu.Lock()
	defer d.mu.Unlock()
	sess := d.window.commissioner
	if sess == nil {
		return
	}
	d.closeSessionLocked(sess)
	d.failedAttemptLocked("the fail-safe expired")
}

// commissioningCompleted closes the window and the PASE sessions once
// CommissioningComplete has committed a fabric.
func (d *Device) commissioningCompleted() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.closeWindowLocked("closed: commissioning completed"); err != nil {
		log.Warnf("device: %v", err)
	}
	for _, sess := range d.sessions {
		if !sess.isCASE {
			d.closeSessionLocked(sess)
		}
	}
}

// closeSessionLocked closes sess and forgets it.
func (d *Device) closeSessionLocked(sess *Session) {
	for id, s := range d.sessions {
		if s == sess {
			delete(d.sessions, id)
		}
	}
	sess.transport.close()
	if d.window.commissioner == sess {
		d.window.commissioner = nil
	}
}

// notifyFabricRemoved tells the application clusters a fabric is gone.
func (d *Device) notifyFabricRemoved(fabricIndex uint8) {
	d.mu.Lock()
	handlers := append([]func(uint8){}, d.fabricRemovedHandlers...)
	d.mu.Unlock()
	for _, h := range handlers {
		h(fabricIndex)
	}
}

// fabricRemoved ends what the removed fabric leaves behind: the sessions
// on it are closed and its operational service withdrawn, and a device
// left on no fabric opens its commissioning window again, as a new device
// does (11.18.6.12).
func (d *Device) fabricRemoved(fabricIndex uint8) {
	d.notifyFabricRemoved(fabricIndex)
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, sess := range d.sessions {
		if sess.fabricIndex == fabricIndex {
			d.closeSessionLocked(sess)
		}
	}
	d.requestRefresh()
	if d.conn == nil || d.window.open {
		return
	}
	fabrics, err := d.store.ListDeviceFabrics()
	if err != nil {
		log.Errorf("device: list the fabrics: %v", err)
		return
	}
	if len(fabrics) == 0 {
		d.service.InstanceName = NewInstanceName()
		if err := d.openWindowLocked(d.initialWindowTimeout, d.basicOpeningLocked(0, 0)); err != nil {
			log.Warnf("device: reopen the commissioning window: %v", err)
		}
	}
}
