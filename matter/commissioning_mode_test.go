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
	"strings"
	"testing"
	"time"

	"github.com/cybergarage/go-matter/matter/ble"
	mdnspkg "github.com/cybergarage/go-matter/matter/mdns"
	"github.com/cybergarage/go-mdns/mdns/dns"
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

// matchingBLEService is a Matter BLE service which advertises the
// payload's vendor, product and discriminator.
type matchingBLEService struct {
	ble.Service
	payload OnboardingPayload
}

func (s *matchingBLEService) VendorID() ble.VendorID   { return s.payload.VendorID() }
func (s *matchingBLEService) ProductID() ble.ProductID { return s.payload.ProductID() }
func (s *matchingBLEService) Discriminator() ble.Discriminator {
	return s.payload.Discriminator()
}

// When the device was found both on the network with CM=0 and over BLE
// without Wi-Fi credentials, the error gives both causes, and does not say
// that the device was found over BLE only.
func TestCommissionReportsBothSkippedDevices(t *testing.T) {
	payload := testPairingCode(t)
	closed := networkDevice(t, payload, modeOf(mdnspkg.CommissioningModeAbsence))
	overBLE := newBLEDevice(nil, &matchingBLEService{payload: payload}, &stubDiscoverer{})
	if !overBLE.MatchesOnboardingPayload(payload) {
		t.Fatal("the test BLE device does not match the payload")
	}

	for _, devs := range [][]CommissionableDevice{{overBLE, closed}, {closed, overBLE}} {
		_, err := (&commissioner{}).commissionMatchingDevice(context.Background(), payload, devs)
		if !errors.Is(err, ErrNotFound) || !errors.Is(err, ErrNotInCommissioningMode) || !errors.Is(err, ErrWiFiNetworkRequired) {
			t.Fatalf("commissionMatchingDevice() error = %v", err)
		}
		if strings.Contains(err.Error(), "only") {
			t.Errorf("commissionMatchingDevice() error = %q, says the device was found one way only", err)
		}
	}
}

// commissionableResponse returns a _matterc._udp response, as a device
// sends it, carrying subtypes and TXT entries, parsed back from its bytes.
func commissionableResponse(t *testing.T, subtypes []string, txt []string) dns.Message {
	t.Helper()
	const (
		instance = "665F6E75B5D3A9C2._matterc._udp.local"
		host     = "B75AFB458ECD6D6F.local"
		ttl      = 120
	)
	must := func(rr dns.ResourceRecord, err error) dns.ResourceRecord {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return rr
	}
	answers := make([]dns.Answer, 0, 1+len(subtypes)+3)
	answers = append(answers, must(dns.NewPTRResourceRecord("_matterc._udp.local", instance, ttl)))
	for _, st := range subtypes {
		answers = append(answers, must(dns.NewPTRResourceRecord(st+"._sub._matterc._udp.local", instance, ttl)))
	}
	answers = append(answers,
		must(dns.NewSRVResourceRecord(instance, 0, 0, 5540, host, ttl)),
		must(dns.NewTXTResourceRecord(instance, txt, ttl)),
		must(dns.NewAResourceRecord(host, net.IPv4(192, 168, 0, 10), ttl)),
	)
	msg := dns.NewResponseMessage(dns.WithMessageAnswers(answers...))
	parsed, err := dns.NewMessageWithBytes(msg.Bytes())
	if err != nil {
		t.Fatalf("dns.NewMessageWithBytes(...) error = %v", err)
	}
	return parsed
}

// The commissioning mode comes from the TXT key CM of a real
// advertisement. A device in commissioning mode advertises the bare _CM
// subtype, which must not read as CM=0, so a device which gives it without
// a CM key is tried. 4.3.1.3, 4.3.1.7.
func TestCommissioningModeOfAnAdvertisement(t *testing.T) {
	base := []string{"D=3840", "VP=65521+32769"}
	for _, tc := range []struct {
		name     string
		subtypes []string
		txt      []string
		mode     mdnspkg.CommissioningMode
		ok       bool
		skipped  bool
	}{
		{"_CM without CM", []string{"_L3840", "_CM"}, base, mdnspkg.CommissioningModeAbsence, false, false},
		{"_CM with CM=1", []string{"_L3840", "_CM"}, append([]string{"CM=1"}, base...), mdnspkg.CommissioningModePasscode, true, false},
		{"_CM with CM=2", []string{"_L3840", "_CM"}, append([]string{"CM=2"}, base...), mdnspkg.CommissioningModeDynamicPasscode, true, false},
		{"CM=0", []string{"_L3840"}, append([]string{"CM=0"}, base...), mdnspkg.CommissioningModeAbsence, true, true},
		{"empty CM", []string{"_L3840"}, append([]string{"CM="}, base...), mdnspkg.CommissioningModeAbsence, false, false},
		{"neither", []string{"_L3840"}, base, mdnspkg.CommissioningModeAbsence, false, false},
	} {
		node, err := mdnspkg.NewCommissioningNodeWithMessage(commissionableResponse(t, tc.subtypes, tc.txt))
		if err != nil {
			t.Fatalf("%s: NewCommissioningNodeWithMessage(...) error = %v", tc.name, err)
		}
		if mode, ok := node.CommissioningMode(); mode != tc.mode || ok != tc.ok {
			t.Errorf("%s: CommissioningMode() = (%v, %v), want (%v, %v)", tc.name, mode, ok, tc.mode, tc.ok)
		}
		if got := notInCommissioningMode(newMDNSDevice(node, &stubDiscoverer{})); got != tc.skipped {
			t.Errorf("%s: notInCommissioningMode() = %v, want %v", tc.name, got, tc.skipped)
		}
	}
}
