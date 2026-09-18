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

	"github.com/cybergarage/go-matter/matter/mdns"
)

// fakeOperationalNode is a minimal mdns.CommissionableNode stand-in that only
// meaningfully implements Addresses()/Port(); every other method returns a
// zero value, since resolveOperationalTransport only looks at those two.
type fakeOperationalNode struct {
	addrs []net.IP
	port  int
}

func (n *fakeOperationalNode) Hostname() (string, bool)                       { return "", false }
func (n *fakeOperationalNode) Addresses() ([]net.IP, bool)                    { return n.addrs, len(n.addrs) > 0 }
func (n *fakeOperationalNode) Port() (int, bool)                              { return n.port, n.port != 0 }
func (n *fakeOperationalNode) VendorID() (mdns.VendorID, bool)                { return 0, false }
func (n *fakeOperationalNode) ProductID() (mdns.ProductID, bool)              { return 0, false }
func (n *fakeOperationalNode) ShortDiscriminator() (mdns.Discriminator, bool) { return 0, false }
func (n *fakeOperationalNode) FullDiscriminator() (mdns.Discriminator, bool)  { return 0, false }
func (n *fakeOperationalNode) Discriminator() (mdns.Discriminator, bool)      { return 0, false }
func (n *fakeOperationalNode) CommissioningMode() (mdns.CommissioningMode, bool) {
	return 0, false
}
func (n *fakeOperationalNode) DeviceType() (mdns.DeviceType, bool)   { return 0, false }
func (n *fakeOperationalNode) DeviceName() (string, bool)            { return "", false }
func (n *fakeOperationalNode) RotatingDeviceID() (string, bool)      { return "", false }
func (n *fakeOperationalNode) PairingHint() (mdns.PairingHint, bool) { return 0, false }
func (n *fakeOperationalNode) PairingInstructions() (string, bool)   { return "", false }
func (n *fakeOperationalNode) String() string                        { return "fakeOperationalNode" }

// fakeRemoteAddrTransport is a minimal caseprotocol.Transport that also
// reports a RemoteAddr, standing in for *mDNSDevice in tests without needing
// a real socket.
type fakeRemoteAddrTransport struct {
	addr net.Addr
}

func (t *fakeRemoteAddrTransport) Transmit(context.Context, []byte) error  { return nil }
func (t *fakeRemoteAddrTransport) Receive(context.Context) ([]byte, error) { return nil, nil }
func (t *fakeRemoteAddrTransport) RemoteAddr() net.Addr                    { return t.addr }

// TestResolveOperationalTransportReusesMatchingConnection guards against a
// real regression: a real device responded instantly and reliably to every
// PASE-phase message, then never responded at all — confirmed via packet
// capture, not just a client-side timeout — to CASE Sigma1 sent from a
// freshly dialed UDP socket (a new local/ephemeral source port) to that
// exact same peer address. Reusing the already-open PASE connection when it
// already points at the operational node's address avoids opening a second,
// new-source-port connection to a peer that has already been talking to us
// fine on the existing one.
func TestResolveOperationalTransportReusesMatchingConnection(t *testing.T) {
	pase := &fakeRemoteAddrTransport{addr: &net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 5540, Zone: "en0"}}
	node := &fakeOperationalNode{addrs: []net.IP{net.ParseIP("fe80::1")}, port: 5540}

	got, err := resolveOperationalTransport(context.Background(), node, pase)
	if err != nil {
		t.Fatalf("resolveOperationalTransport(...) error = %v", err)
	}
	if got != pase {
		t.Error("resolveOperationalTransport(...) did not reuse the matching PASE transport")
	}
}

func TestResolveOperationalTransportDialsFreshOnAddressMismatch(t *testing.T) {
	pase := &fakeRemoteAddrTransport{addr: &net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 5540, Zone: "en0"}}
	// A node address that does not match the PASE transport's peer at all.
	// UDP dialing doesn't probe reachability, so this succeeds regardless —
	// the point here is only that resolveOperationalTransport did NOT reuse
	// pase for an address it was never dialed to.
	node := &fakeOperationalNode{addrs: []net.IP{net.ParseIP("203.0.113.1")}, port: 5540}

	got, err := resolveOperationalTransport(context.Background(), node, pase)
	if err != nil {
		t.Fatalf("resolveOperationalTransport(...) error = %v", err)
	}
	if got == pase {
		t.Error("resolveOperationalTransport(...) reused the PASE transport despite a non-matching operational address")
	}
	if closer, ok := got.(interface{ Close() error }); ok {
		_ = closer.Close()
	}
}

func TestResolveOperationalTransportDialsFreshWhenPASETransportUnavailable(t *testing.T) {
	node := &fakeOperationalNode{addrs: []net.IP{net.ParseIP("203.0.113.1")}, port: 5540}

	got, err := resolveOperationalTransport(context.Background(), node, nil)
	if err != nil {
		t.Fatalf("resolveOperationalTransport(...) error = %v", err)
	}
	if got == nil {
		t.Error("resolveOperationalTransport(...) returned a nil transport with no error")
	}
	if closer, ok := got.(interface{ Close() error }); ok {
		_ = closer.Close()
	}
}
