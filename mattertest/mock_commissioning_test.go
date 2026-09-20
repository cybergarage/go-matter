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

package mattertest

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter"
	"github.com/cybergarage/go-matter/matter/config"
	"github.com/cybergarage/go-matter/matter/encoding"
	"github.com/cybergarage/go-matter/mattertest/mockdevice"
)

// Milestone 7 of the mock-device commissioning test plan: the fully
// assembled end-to-end test. Unlike TestCommissioner (gated behind
// MATTER_TEST_COMMISSIONER_LIVE, only runs against real hardware), this
// test has no gate — it runs in plain `go test ./mattertest/...`/CI — and
// commissions an entirely in-process mockdevice.Device instead, so every
// bug class fixed against a real device earlier in this project's history
// (raw-vs-HKDF-derived IPK, DER-vs-TLV certificates, missing MRP ack
// counters, missing NOC ExtKeyUsage purposes, ...) now has an automated
// regression test that doesn't need hardware to catch a reoccurrence.

// mockCommissioningDiscriminator/mockCommissioningPasscode/
// mockCommissioningVendorID/mockCommissioningProductID are a synthetic
// identity for this test's mock device, unrelated to any real device's
// actual values (confirmed with the user: the MPC used here must not be
// the real device's).
const (
	mockCommissioningDiscriminator = 0x0ABC
	mockCommissioningPasscode      = 20202021
	mockCommissioningVendorID      = 0xFFF1
	mockCommissioningProductID     = 0x8001
)

func TestMockCommissioning(t *testing.T) {
	log.EnableStdoutDebug(true)
	defer log.EnableStdoutDebug(false)

	dev, err := mockdevice.New(
		mockdevice.WithDiscriminator(mockCommissioningDiscriminator),
		mockdevice.WithPasscode(mockCommissioningPasscode),
		mockdevice.WithVendorID(mockCommissioningVendorID),
		mockdevice.WithProductID(mockCommissioningProductID),
	)
	if err != nil {
		t.Fatalf("mockdevice.New() error = %v", err)
	}
	if err := dev.Start(); err != nil {
		t.Fatalf("Device.Start() error = %v", err)
	}
	defer func() {
		if err := dev.Stop(); err != nil {
			t.Errorf("Device.Stop() error = %v", err)
		}
	}()

	mpc := buildManualPairingCodeForTest(t, mockCommissioningDiscriminator, mockCommissioningPasscode, mockCommissioningVendorID, mockCommissioningProductID)
	pairingCode, err := encoding.NewPairingCodeFromString(mpc)
	if err != nil {
		t.Fatalf("encoding.NewPairingCodeFromString(%q) error = %v", mpc, err)
	}

	adminCfg, err := NewAdministratorConfig()
	if err != nil {
		t.Fatalf("NewAdministratorConfig() error = %v", err)
	}
	opCfg := config.NewOperationalCredentialConfig(
		config.WithIPK(defaultOperationalIPK),
		config.WithCASEAdminNodeID(testAdministratorNodeID),
		config.WithAdminVendorID(defaultAdminVendorID),
	)

	cmr := matter.NewCommissioner(matter.WithCommissionerDiscoverer(mockdevice.NewFakeDiscoverer(dev)))
	if err := cmr.Start(); err != nil {
		t.Fatalf("Commissioner.Start() error = %v", err)
	}
	defer func() {
		if err := cmr.Stop(); err != nil {
			t.Errorf("Commissioner.Stop() error = %v", err)
		}
	}()

	// Commissioner.Discover (matter/commissioner_impl.go) runs BLE scanning
	// and mDNS discovery in parallel and waits for both, using this ctx's
	// own deadline verbatim once it has one (it only falls back to its own
	// shorter DefaultDiscoveryTimeout when ctx has none) — so a generous
	// deadline here would make this test block for that long on a machine
	// with no real BLE adapter to satisfy the scan. The fake discoverer
	// this test injects answers immediately, so a short deadline is enough;
	// the commissioning phase itself that follows discovery is governed by
	// matter.DefaultCommissioningTimeout, not this ctx.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cme, err := cmr.Commission(ctx, pairingCode, adminCfg, opCfg)
	if err != nil {
		t.Fatalf("Failed to commission mock device: %v", err)
	}
	t.Logf("Successfully commissioned mock device: %s", cme.String())

	select {
	case <-dev.CommissioningCompleted():
	case <-time.After(1 * time.Second):
		t.Error("Device.CommissioningCompleted() did not fire after Commission() returned success")
	}
}

// buildManualPairingCodeForTest encodes an 11/21-digit Manual Pairing Code
// string, mirroring matter/encoding/pairing.go's own (unexported)
// encodeManualPairingCode — reimplemented here since mattertest is a
// separate package and can't reach it directly. Always produces the
// 21-digit long form (vendorID/productID present), per this project's own
// decision to exercise that branch rather than the 11-digit short form's
// coarser (top-4-bits-only) discriminator encoding.
func buildManualPairingCodeForTest(t *testing.T, discriminator uint16, passcode uint32, vendorID, productID uint16) string {
	t.Helper()
	d1 := (uint16(1) << 2) | ((discriminator >> 10) & 0x3)
	d26 := (uint32(discriminator&0x300) << 6) | (uint32(passcode) & 0x3FFF)
	d710 := (passcode >> 14) & 0x3FFF
	code := fmt.Sprintf("%01d%05d%04d%05d%05d", d1, d26, d710, vendorID, productID)
	return code + string(verhoeffCheckDigitForTest(code))
}

// verhoeffCheckDigitForTest computes a Verhoeff checksum digit — the
// standard ISO/IEC 7064-family algorithm Manual Pairing Codes use for
// error detection, not Matter-specific logic, so independently
// reimplementing the standard tables here (rather than needing access to
// matter/encoding's unexported generateVerhoeffCheck) carries none of the
// protocol-specific-formula risk this project's CASE/PASE work does.
func verhoeffCheckDigitForTest(numStr string) byte {
	d := [][]int{
		{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
		{1, 2, 3, 4, 0, 6, 7, 8, 9, 5},
		{2, 3, 4, 0, 1, 7, 8, 9, 5, 6},
		{3, 4, 0, 1, 2, 8, 9, 5, 6, 7},
		{4, 0, 1, 2, 3, 9, 5, 6, 7, 8},
		{5, 9, 8, 7, 6, 0, 4, 3, 2, 1},
		{6, 5, 9, 8, 7, 1, 0, 4, 3, 2},
		{7, 6, 5, 9, 8, 2, 1, 0, 4, 3},
		{8, 7, 6, 5, 9, 3, 2, 1, 0, 4},
		{9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
	}
	p := [][]int{
		{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
		{1, 5, 7, 6, 2, 8, 3, 0, 9, 4},
		{5, 8, 0, 3, 7, 9, 6, 1, 4, 2},
		{8, 9, 1, 6, 0, 4, 3, 5, 2, 7},
		{9, 4, 5, 3, 1, 2, 6, 8, 7, 0},
		{4, 2, 8, 6, 5, 7, 3, 9, 0, 1},
		{2, 7, 9, 3, 8, 0, 6, 4, 1, 5},
		{7, 0, 4, 6, 9, 1, 3, 2, 5, 8},
	}
	inv := []int{0, 4, 3, 2, 1, 5, 6, 7, 8, 9}

	withPlaceholder := numStr + "0"
	c := 0
	for i := range len(withPlaceholder) {
		digit := int(withPlaceholder[len(withPlaceholder)-1-i] - '0')
		c = d[c][p[i%8][digit]]
	}
	return byte('0' + inv[c])
}
