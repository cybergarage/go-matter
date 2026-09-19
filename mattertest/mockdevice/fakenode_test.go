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
	"crypto/x509"
	"testing"

	"github.com/cybergarage/go-matter/matter/mdns"
)

func TestFakeDiscovererCommissionableNodeQuery(t *testing.T) {
	dev, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := dev.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() { _ = dev.Stop() })

	disc := NewFakeDiscoverer(dev)
	nodes, err := disc.Search(context.Background(), mdns.NewQuery(mdns.WithQueryService(mdns.CommissionableNodeService)))
	if err != nil {
		t.Fatalf("Search(commissionable) error = %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("Search(commissionable) returned %d nodes, want 1", len(nodes))
	}
	node := nodes[0]
	if vid, ok := node.VendorID(); !ok || vid != mdns.VendorID(dev.VendorID()) {
		t.Errorf("node.VendorID() = (%v, %v), want (%v, true)", vid, ok, dev.VendorID())
	}
	if pid, ok := node.ProductID(); !ok || pid != mdns.ProductID(dev.ProductID()) {
		t.Errorf("node.ProductID() = (%v, %v), want (%v, true)", pid, ok, dev.ProductID())
	}
	if disc, ok := node.Discriminator(); !ok || disc != mdns.Discriminator(dev.Discriminator()) {
		t.Errorf("node.Discriminator() = (%v, %v), want (%v, true)", disc, ok, dev.Discriminator())
	}
	port, ok := node.Port()
	if !ok || port != dev.Addr().Port {
		t.Errorf("node.Port() = (%v, %v), want (%v, true)", port, ok, dev.Addr().Port)
	}
}

func TestFakeDiscovererOperationalNodeQueryBeforeAddNOC(t *testing.T) {
	dev, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := dev.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() { _ = dev.Stop() })

	disc := NewFakeDiscoverer(dev)
	nodes, err := disc.Search(context.Background(), mdns.NewOperationalNodeQuery("0000000000000001-0000000000000001"))
	if err != nil {
		t.Fatalf("Search(operational) error = %v", err)
	}
	if len(nodes) != 0 {
		t.Errorf("Search(operational) before AddNOC returned %d nodes, want 0", len(nodes))
	}
}

func TestFakeDiscovererOperationalNodeQueryAfterAddNOC(t *testing.T) {
	rootDER, rootKeyDER, rootKey := generateTestRootCA(t)
	rootCertParsed, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("parse root certificate: %v", err)
	}
	const fabricID = 0x00000000AAAAAAAA
	const nodeID = 0x00000000DEADBEEF

	nocDER, _ := issueOperationalNOC(t, rootCertParsed, rootKey, fabricID, nodeID)

	dev, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := dev.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() { _ = dev.Stop() })

	dev.fs.rootCertDER = rootDER
	dev.fs.nocDER = nocDER
	dev.fs.fabricID = fabricID
	dev.fs.nodeID = nodeID
	_ = rootKeyDER

	instance, ok := dev.operationalServiceInstance()
	if !ok {
		t.Fatal("operationalServiceInstance() ok = false after AddNOC-equivalent state was set")
	}

	disc := NewFakeDiscoverer(dev)
	nodes, err := disc.Search(context.Background(), mdns.NewOperationalNodeQuery(instance))
	if err != nil {
		t.Fatalf("Search(operational) error = %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("Search(operational) with the right instance name returned %d nodes, want 1", len(nodes))
	}

	nodes, err = disc.Search(context.Background(), mdns.NewOperationalNodeQuery("0000000000000000-0000000000000000"))
	if err != nil {
		t.Fatalf("Search(operational, wrong instance) error = %v", err)
	}
	if len(nodes) != 0 {
		t.Errorf("Search(operational) with the wrong instance name returned %d nodes, want 0", len(nodes))
	}
}
