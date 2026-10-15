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
	"net"
	"testing"

	mdnspkg "github.com/cybergarage/go-matter/matter/mdns"
)

// stubOperationalNode is a response of an operational discovery.
type stubOperationalNode struct {
	mdnspkg.CommissionableNode
	port  int
	addrs []net.IP
}

func (n *stubOperationalNode) Port() (int, bool)           { return n.port, n.port != 0 }
func (n *stubOperationalNode) Addresses() ([]net.IP, bool) { return n.addrs, len(n.addrs) != 0 }

// namedOperationalNode is one which names its service, as go-mdns's do.
type namedOperationalNode struct {
	stubOperationalNode
	name string
}

func (n *namedOperationalNode) Name() string { return n.name }

func TestSelectOperationalNode(t *testing.T) {
	const instance = "743205D875DE5E8E-6FDF3ADC3DF68CF7"
	addr := []net.IP{net.ParseIP("192.168.100.49")}
	unspecified := []net.IP{net.IPv4zero}
	commissionable := &namedOperationalNode{stubOperationalNode{port: 5540, addrs: addr}, "03182FB2AAACE0FC._matterc._udp"}
	noAddress := &namedOperationalNode{stubOperationalNode{port: 5540, addrs: unspecified}, instance + "._matter._tcp"}
	withAddress := &namedOperationalNode{stubOperationalNode{port: 5540, addrs: addr}, instance + "._matter._tcp"}
	otherNode := &namedOperationalNode{stubOperationalNode{port: 5540, addrs: addr}, "743205D875DE5E8E-0000000000000001._matter._tcp"}

	// The responses of a device which has just joined its network, in the
	// order they arrived: its commissionable service first, its
	// operational service before it has an address, then with one.
	node, ok := selectOperationalNode([]mdnspkg.CommissionableNode{commissionable, noAddress, withAddress, otherNode}, instance)
	if !ok || node != withAddress {
		t.Fatalf("selectOperationalNode() = %v, %t; want the operational service with an address", node, ok)
	}
	if _, ok := selectOperationalNode([]mdnspkg.CommissionableNode{commissionable, noAddress, otherNode}, instance); ok {
		t.Fatal("a node without an address, or of another service, selected")
	}
	if _, ok := selectOperationalNode([]mdnspkg.CommissionableNode{&namedOperationalNode{stubOperationalNode{addrs: addr}, instance + "._matter._tcp"}}, instance); ok {
		t.Fatal("a node without a port selected")
	}
	// A node which does not name its service, such as a test double, is
	// taken on its port and address alone.
	unnamed := &stubOperationalNode{port: 5540, addrs: addr}
	if node, ok := selectOperationalNode([]mdnspkg.CommissionableNode{unnamed}, instance); !ok || node != unnamed {
		t.Fatal("an unnamed node with a port and an address not selected")
	}
	if _, ok := selectOperationalNode(nil, instance); ok {
		t.Fatal("no node selected from no responses")
	}
}

// untilDiscoverer answers a SearchUntil with its responses, stopping at the
// first one accept takes, and fails a Search.
type untilDiscoverer struct {
	mdnspkg.Discoverer
	t         *testing.T
	responses []mdnspkg.CommissionableNode
	offered   int
}

func (d *untilDiscoverer) Search(context.Context, mdnspkg.Query) ([]mdnspkg.CommissionableNode, error) {
	d.t.Fatal("Search used although the discoverer can end a search early")
	return nil, nil
}

func (d *untilDiscoverer) SearchUntil(_ context.Context, _ mdnspkg.Query, accept func(mdnspkg.CommissionableNode) bool) ([]mdnspkg.CommissionableNode, error) {
	var seen []mdnspkg.CommissionableNode
	for _, node := range d.responses {
		d.offered++
		seen = append(seen, node)
		if accept(node) {
			break
		}
	}
	return seen, nil
}

func TestSearchOperationalNodesEndsAtTheFirstUsableResponse(t *testing.T) {
	const instance = "743205D875DE5E8E-B6C144BE822A44BA"
	addr := []net.IP{net.ParseIP("192.168.100.49")}
	noAddress := &namedOperationalNode{stubOperationalNode{port: 5540, addrs: []net.IP{net.IPv4zero}}, instance + "._matter._tcp"}
	usable := &namedOperationalNode{stubOperationalNode{port: 5540, addrs: addr}, instance + "._matter._tcp"}
	later := &namedOperationalNode{stubOperationalNode{port: 5540, addrs: addr}, instance + "._matter._tcp"}
	d := &untilDiscoverer{t: t, responses: []mdnspkg.CommissionableNode{noAddress, usable, later}}

	nodes, err := searchOperationalNodes(context.Background(), d, instance)
	if err != nil {
		t.Fatal(err)
	}
	if d.offered != 2 {
		t.Fatalf("the search went on after a usable response: %d responses offered", d.offered)
	}
	if node, ok := selectOperationalNode(nodes, instance); !ok || node != usable {
		t.Fatal("the usable response was not selected")
	}
}
