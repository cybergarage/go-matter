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

package mockdevice

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	"net"

	"github.com/cybergarage/go-matter/matter/mdns"
)

// fakeCommissionableNode is a minimal mdns.CommissionableNode advertising a
// Device's loopback address/port and identity. Only the fields
// matter.baseDevice.matchesOnboardingPayload actually checks (VendorID,
// ProductID, Discriminator) and Addresses/Port (needed to actually open a
// connection) are meaningful; everything else reports absent, matching
// what a real, minimal commissionable node advertisement might omit.
type fakeCommissionableNode struct {
	addr          net.IP
	port          int
	vendorID      uint16
	productID     uint16
	discriminator uint16
}

func (n *fakeCommissionableNode) Hostname() (string, bool)    { return "", false }
func (n *fakeCommissionableNode) Addresses() ([]net.IP, bool) { return []net.IP{n.addr}, true }
func (n *fakeCommissionableNode) Port() (int, bool)           { return n.port, true }
func (n *fakeCommissionableNode) VendorID() (mdns.VendorID, bool) {
	return mdns.VendorID(n.vendorID), true
}
func (n *fakeCommissionableNode) ProductID() (mdns.ProductID, bool) {
	return mdns.ProductID(n.productID), true
}
func (n *fakeCommissionableNode) ShortDiscriminator() (mdns.Discriminator, bool) {
	return 0, false
}
func (n *fakeCommissionableNode) FullDiscriminator() (mdns.Discriminator, bool) {
	return mdns.Discriminator(n.discriminator), true
}
func (n *fakeCommissionableNode) Discriminator() (mdns.Discriminator, bool) {
	return mdns.Discriminator(n.discriminator), true
}
func (n *fakeCommissionableNode) CommissioningMode() (mdns.CommissioningMode, bool) {
	return 0, false
}
func (n *fakeCommissionableNode) DeviceType() (mdns.DeviceType, bool)   { return 0, false }
func (n *fakeCommissionableNode) DeviceName() (string, bool)            { return "", false }
func (n *fakeCommissionableNode) RotatingDeviceID() (string, bool)      { return "", false }
func (n *fakeCommissionableNode) PairingHint() (mdns.PairingHint, bool) { return 0, false }
func (n *fakeCommissionableNode) PairingInstructions() (string, bool)   { return "", false }
func (n *fakeCommissionableNode) String() string {
	return fmt.Sprintf("mockdevice.fakeCommissionableNode{addr=%s port=%d}", n.addr, n.port)
}

// fakeDiscoverer implements mdns.Discoverer over a single mockdevice.Device,
// for injection via matter.WithCommissionerDiscoverer. It answers two query
// shapes, matching how matter/commissioner_impl.go's Discover and
// matter/commissioning_impl.go's discoverOperationalNode each use it:
// commissionable-node discovery (any time), and operational-node discovery
// by exact service instance name (only once AddNOC has actually run — the
// compressed fabric ID/node ID identity doesn't exist before that).
type fakeDiscoverer struct {
	dev *Device
}

// NewFakeDiscoverer returns an mdns.Discoverer that only ever "discovers"
// dev — for tests that need matter.Commissioner to find and commission an
// in-process mockdevice.Device instead of scanning the real network.
func NewFakeDiscoverer(dev *Device) mdns.Discoverer {
	return &fakeDiscoverer{dev: dev}
}

func (f *fakeDiscoverer) Start() error { return nil }
func (f *fakeDiscoverer) Stop() error  { return nil }

func (f *fakeDiscoverer) Search(_ context.Context, query mdns.Query) ([]mdns.CommissionableNode, error) {
	node := &fakeCommissionableNode{
		addr:          net.ParseIP("127.0.0.1"),
		port:          f.dev.Addr().Port,
		vendorID:      f.dev.VendorID(),
		productID:     f.dev.ProductID(),
		discriminator: f.dev.Discriminator(),
	}

	service := query.Service()
	if service == mdns.CommissionableNodeService {
		return []mdns.CommissionableNode{node}, nil
	}

	operationalServiceInstance, ok := f.dev.operationalServiceInstance()
	if ok && service == operationalServiceInstance+"."+mdns.OperationalNodeService {
		return []mdns.CommissionableNode{node}, nil
	}

	// No match: either an unrecognized query, or an operational-node query
	// asked before AddNOC has run — both legitimately return no results,
	// matching a real mdns.Discoverer's behavior for a target that isn't
	// (yet) advertising under that name.
	return nil, nil
}

// operationalServiceInstance computes "<compressedFabricID>-<nodeID>" (the
// same format matter/commissioning_impl.go's loadOperationalCASEPeer
// builds), independently from this package's own computeCompressedFabricIDBytes
// rather than matter/protocol/case's unexported equivalent — consistent
// with case_crypto.go's independence rationale. Returns ok=false before
// AddNOC has populated the fabric state.
func (d *Device) operationalServiceInstance() (string, bool) {
	if len(d.fs.rootCertDER) == 0 || len(d.fs.nocDER) == 0 {
		return "", false
	}
	rootCert, err := x509.ParseCertificate(d.fs.rootCertDER)
	if err != nil {
		return "", false
	}
	rootPub, ok := rootCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return "", false
	}
	rootPublicKeyBytes := elliptic.Marshal(rootPub.Curve, rootPub.X, rootPub.Y)
	compressedFabricIDBytes, err := computeCompressedFabricIDBytes(rootPublicKeyBytes, d.fs.fabricID)
	if err != nil {
		return "", false
	}
	compressedFabricID := uint64(0)
	for _, b := range compressedFabricIDBytes {
		compressedFabricID = compressedFabricID<<8 | uint64(b)
	}
	return fmt.Sprintf("%016X-%016X", compressedFabricID, d.fs.nodeID), true
}
