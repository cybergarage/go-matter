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
	"time"

	"github.com/cybergarage/go-matter/matter/ble"
	"github.com/cybergarage/go-matter/matter/mdns"
)

const (
	// DefaultDiscoveryTimeout is the default discovery timeout.
	DefaultDiscoveryTimeout = time.Duration(5 * time.Second)
	// DefaultCommissioningTimeout is the default commissioning timeout,
	// bounding the entire PASE-through-CASE commissioning exchange (dozens
	// of round trips: PASE handshake, ArmFailSafe, device attestation,
	// CSR/NOC issuance, AddTrustedRootCertificate, AddNOC, operational mDNS
	// discovery, CASE). The connection's read/write deadlines are derived
	// from this single ctx.Deadline() set once at the start of Commission(),
	// not reset per round trip. 5 seconds proved far too short against a
	// real device (AddNOC alone can take several seconds while the device
	// commits the new fabric to persistent storage); 60 seconds later also
	// proved too short once AddNOC actually succeeded end to end — after
	// joining the fabric, the device re-advertises itself operationally over
	// mDNS, and CASE has to rediscover it via that new record before Sigma1
	// can be sent, which on a busy network with many other mDNS-chatty
	// devices was observed taking ~55s by itself, expiring the deadline
	// mid-CASE ("write udp ...: i/o timeout" on Sigma1, at exactly the 60s
	// mark). 120 seconds matches armFailSafeExpiry in commissioning_impl.go:
	// the device's own fail-safe timer, which the commissioner is racing
	// against regardless, is already set to that duration.
	DefaultCommissioningTimeout = time.Duration(120 * time.Second)
)

// Commissioner represents a commissioner interface.
type Commissioner interface {
	// Scannar returns the BLE scanner.
	Scannar() ble.Scanner
	// Discoverer returns the mDNS discoverer.
	Discoverer() mdns.Discoverer
	// Discover discovers commissionable devices with the given query.
	// 5.4.3. Discovery by Commissioner
	Discover(ctx context.Context, query Query) ([]CommissionableDevice, error)
	// Commission commissions a device with the given onboarding payload.
	Commission(ctx context.Context, payload OnboardingPayload, opts ...CommissionOption) (Commissionee, error)
	// Start starts the commissioner.
	Start() error
	// Stop stops the commissioner.
	Stop() error
}
