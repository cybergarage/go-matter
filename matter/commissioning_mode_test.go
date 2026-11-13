// Copyright (C) 2024 The go-matter Authors. All rights reserved.
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
	"net"
	"testing"
	"time"

	mdnspkg "github.com/cybergarage/go-matter/matter/mdns"
)

// commissionableNode is an mdns.CommissionableNode which advertises a
// commissioning mode, as a device on the network does.
type commissionableNode struct {
	fakeOperationalNode
	vendorID      mdnspkg.VendorID
	productID     mdnspkg.ProductID
	discriminator mdnspkg.Discriminator
	mode          *mdnspkg.CommissioningMode
}

func (n *commissionableNode) VendorID() (mdnspkg.VendorID, bool)   { return n.vendorID, true }
func (n *commissionableNode) ProductID() (mdnspkg.ProductID, bool) { return n.productID, true }
func (n *commissionableNode) Discriminator() (mdnspkg.Discriminator, bool) {
	return n.discriminator, true
}

func (n *commissionableNode) CommissioningMode() (mdnspkg.CommissioningMode, bool) {
	if n.mode == nil {
		return mdnspkg.CommissioningModeAbsence, false
	}
	return *n.mode, true
}

func networkDevice(t *testing.T, payload OnboardingPayload, mode *mdnspkg.CommissioningMode) CommissionableDevice {
	t.Helper()
	node := &commissionableNode{
		// No address: a device which is tried fails at once.
		fakeOperationalNode: fakeOperationalNode{addrs: []net.IP{}, port: 0},
		vendorID:            mdnspkg.VendorID(payload.VendorID()),
		productID:           mdnspkg.ProductID(payload.ProductID()),
		discriminator:       mdnspkg.Discriminator(payload.Discriminator()),
		mode:                mode,
	}
	dev := newMDNSDevice(node, &stubDiscoverer{})
	if !dev.MatchesOnboardingPayload(payload) {
		t.Fatal("the test device does not match the payload")
	}
	return dev
}

func modeOf(m mdnspkg.CommissioningMode) *mdnspkg.CommissioningMode { return &m }

// A device on the network with CM=0 has no commissioning window open: it is
// not tried, and the error says why, instead of PASE waiting for the
// commissioning timeout.
func TestCommissionSkipsADeviceNotInCommissioningMode(t *testing.T) {
	payload := testPairingCode(t)
	closed := networkDevice(t, payload, modeOf(mdnspkg.CommissioningModeAbsence))

	start := time.Now()
	_, err := (&commissioner{}).commissionMatchingDevice(context.Background(), payload, []CommissionableDevice{closed})
	if !errors.Is(err, ErrNotInCommissioningMode) || !errors.Is(err, ErrNotFound) {
		t.Fatalf("commissionMatchingDevice() error = %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("returned after %v", elapsed)
	}
}

// A device in commissioning mode, or one which does not say, is tried.
func TestCommissionTriesADeviceInCommissioningModeOrNotSaying(t *testing.T) {
	payload := testPairingCode(t)
	for name, mode := range map[string]*mdnspkg.CommissioningMode{
		"CM=1":      modeOf(mdnspkg.CommissioningModePasscode),
		"CM=2":      modeOf(mdnspkg.CommissioningModeDynamicPasscode),
		"no CM key": nil,
	} {
		dev := networkDevice(t, payload, mode)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, err := (&commissioner{}).commissionMatchingDevice(ctx, payload, []CommissionableDevice{dev})
		cancel()
		// The device has no address, so the attempt fails; it must have
		// been attempted rather than skipped.
		if err == nil || errors.Is(err, ErrNotInCommissioningMode) || !errors.Is(err, ErrFailed) {
			t.Errorf("%s: commissionMatchingDevice() error = %v", name, err)
		}
	}
}

// Other devices are still tried when one on the network is closed: here a
// matching stub device after it.
func TestCommissionMovesOnFromADeviceNotInCommissioningMode(t *testing.T) {
	payload := testPairingCode(t)
	closed := networkDevice(t, payload, modeOf(mdnspkg.CommissioningModeAbsence))
	open := &stubCommissionableDevice{match: true}
	if _, err := (&commissioner{}).commissionMatchingDevice(context.Background(), payload, []CommissionableDevice{closed, open}); err != nil {
		t.Fatalf("commissionMatchingDevice() error = %v", err)
	}
	if open.gotCalls != 1 {
		t.Fatalf("the device in commissioning mode was tried %d times", open.gotCalls)
	}
}
