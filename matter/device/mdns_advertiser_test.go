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
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/cybergarage/go-matter/matter/mdns"
	"github.com/cybergarage/go-matter/matter/protocol/pase"
	gomdns "github.com/cybergarage/go-mdns/mdns"
)

func TestCommissionableLocalService(t *testing.T) {
	svc := testService()
	local := commissionableLocalService(svc)
	if local.FullName() != svc.InstanceFullName() {
		t.Errorf("FullName() = %q, want %q", local.FullName(), svc.InstanceFullName())
	}
	if local.HostName() != svc.HostFullName() {
		t.Errorf("HostName() = %q, want %q", local.HostName(), svc.HostFullName())
	}
	if err := local.Validate(); err != nil {
		t.Errorf("Validate() = %v", err)
	}
}

// TestDeviceIsDiscoveredAndCommissionable runs the whole path a commissioner
// takes before commissioning over IP: it finds the device with go-matter's
// own discovery by the device's long discriminator, over real mDNS, and
// establishes PASE with it at the discovered address and port.
func TestDeviceIsDiscoveredAndCommissionable(t *testing.T) {
	if testing.Short() {
		t.Skip("uses mDNS on the network; skipped with -short")
	}
	const discriminator = 0x0ABC
	sessions := make(chan *Session, 1)
	d, err := New(
		WithPasscode(testPasscode),
		WithAddress(":0"),
		WithDiscriminator(discriminator),
		WithVendorID(0xFFF1),
		WithProductID(0x8001),
		WithSessionHandler(func(s *Session) { sessions <- s }),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Start(); err != nil {
		t.Skipf("the device cannot advertise here: %v", err)
	}
	defer d.Stop()

	disc := mdns.NewDiscoverer()
	if err := disc.Start(); err != nil {
		t.Skipf("the discoverer cannot bind the mDNS sockets here: %v", err)
	}
	defer disc.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	query := mdns.NewQuery(mdns.WithQuerySubtype(mdns.QuerySubtypeLongDiscriminator + strconv.Itoa(discriminator)))
	var node mdns.CommissionableNode
	for node == nil && ctx.Err() == nil {
		// Search collects the answers until its context ends.
		searchCtx, cancelSearch := context.WithTimeout(ctx, 2*time.Second)
		nodes, err := disc.Search(searchCtx, query)
		cancelSearch()
		if err != nil {
			t.Fatalf("Search(...) error = %v", err)
		}
		for _, n := range nodes {
			if d, ok := n.FullDiscriminator(); ok && uint16(d) == discriminator {
				node = n
			}
		}
	}
	if node == nil {
		t.Fatal("the device was not discovered by its long discriminator")
	}
	if vid, ok := node.VendorID(); !ok || uint16(vid) != 0xFFF1 {
		t.Errorf("discovered VendorID() = (%v, %v), want 0xFFF1", vid, ok)
	}
	if cm, ok := node.CommissioningMode(); !ok || cm != mdns.CommissioningModePasscode {
		t.Errorf("discovered CommissioningMode() = (%v, %v), want 1", cm, ok)
	}
	port, ok := node.Port()
	if !ok || port != d.CommissionableService().Port {
		t.Fatalf("discovered Port() = (%d, %v), want %d", port, ok, d.CommissionableService().Port)
	}
	addrs, ok := node.Addresses()
	if !ok {
		t.Fatal("the device was discovered without an address")
	}

	// PASE at the first discovered IPv4 address the device answers on.
	var lastErr error
	for _, ip := range addrs {
		if ip.To4() == nil {
			continue
		}
		conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: ip, Port: port})
		if err != nil {
			lastErr = err
			continue
		}
		attempt, cancelAttempt := context.WithTimeout(ctx, 3*time.Second)
		_, lastErr = pase.NewInitiator(&udpClient{conn: conn}, testPasscode).EstablishSession(attempt)
		cancelAttempt()
		_ = conn.Close()
		if lastErr == nil {
			break
		}
	}
	if lastErr != nil {
		t.Fatalf("PASE at the discovered addresses %v: %v", addrs, lastErr)
	}
	select {
	case <-sessions:
	case <-ctx.Done():
		t.Fatal("the session handler was not called")
	}
}

// startOtherNode starts a go-mdns server which plays another node on the
// link, and publishes svc with it.
func startOtherNode(t *testing.T, svc *gomdns.LocalService) {
	t.Helper()
	if testing.Short() {
		t.Skip("uses mDNS on the network; skipped with -short")
	}
	server := gomdns.NewServer()
	if err := server.Start(); err != nil {
		t.Skipf("the server cannot bind the mDNS sockets here: %v", err)
	}
	t.Cleanup(func() { _ = server.Stop() })
	if err := server.Register(context.Background(), svc); err != nil {
		t.Fatal(err)
	}
}

// otherNodeService returns the service another node publishes with the
// given instance name and host, on another port and address than the
// device's.
func otherNodeService(service, instance, host string) *gomdns.LocalService {
	return &gomdns.LocalService{
		Instance:  instance,
		Service:   service,
		Domain:    ServiceDomain,
		Host:      host,
		Port:      15540,
		TXT:       []string{"D=1"},
		Addresses: []net.IP{net.IPv4(192, 0, 2, 77)},
	}
}

// uniqueCommissionableService returns a commissionable service with random
// names, so that the tests on a shared link do not see each other.
func uniqueCommissionableService() CommissionableService {
	svc := testService()
	svc.InstanceName = NewInstanceName()
	svc.Hostname = NewHostname()
	return svc
}

func TestMDNSAdvertiserRenamesCommissionableOnConflict(t *testing.T) {
	svc := uniqueCommissionableService()
	startOtherNode(t, otherNodeService(CommissionableServiceType, svc.InstanceName, NewHostname()))

	adv := NewMDNSAdvertiser()
	defer adv.Withdraw()
	if err := adv.AdvertiseCommissionable(svc); err != nil {
		t.Fatalf("AdvertiseCommissionable() = %v", err)
	}
	renamed, ok := adv.CommissionableInstanceName()
	if !ok || renamed == svc.InstanceName {
		t.Fatalf("published instance name = (%q, %v), want a new name for %q", renamed, ok, svc.InstanceName)
	}

	// The device advertises the same service again, such as after a failed
	// commissioning attempt: the renamed instance is kept.
	if err := adv.WithdrawCommissionable(); err != nil {
		t.Fatal(err)
	}
	if err := adv.AdvertiseCommissionable(svc); err != nil {
		t.Fatalf("AdvertiseCommissionable() again = %v", err)
	}
	if again, _ := adv.CommissionableInstanceName(); again != renamed {
		t.Errorf("published instance name = %q after advertising again, want %q", again, renamed)
	}
}

func TestMDNSAdvertiserCommissionableHostConflict(t *testing.T) {
	svc := uniqueCommissionableService()
	startOtherNode(t, otherNodeService("_http._tcp", NewInstanceName(), svc.Hostname))

	adv := NewMDNSAdvertiser()
	defer adv.Withdraw()
	err := adv.AdvertiseCommissionable(svc)
	var conflict *gomdns.ConflictError
	if !errors.As(err, &conflict) || !conflict.IsHostConflict() {
		t.Fatalf("AdvertiseCommissionable() = %v, want a host conflict", err)
	}
	if _, ok := adv.CommissionableInstanceName(); ok {
		t.Error("the commissionable service is published after a host conflict")
	}
}

func TestMDNSAdvertiserOperationalConflict(t *testing.T) {
	op := testOperationalService()
	op.NodeID = uint64(time.Now().UnixNano()) | 1
	op.Hostname = NewHostname()
	startOtherNode(t, otherNodeService(OperationalServiceType, op.InstanceName(), NewHostname()))

	adv := NewMDNSAdvertiser()
	defer adv.Withdraw()
	err := adv.AdvertiseOperational([]OperationalService{op})
	var conflict *gomdns.ConflictError
	if !errors.As(err, &conflict) || !conflict.IsInstanceConflict() {
		t.Fatalf("AdvertiseOperational() = %v, want an instance conflict", err)
	}
	if conflict.Service.Instance != op.InstanceName() {
		t.Errorf("the operational instance was renamed to %q", conflict.Service.Instance)
	}
}

func TestMDNSAdvertiserHandleConflict(t *testing.T) {
	if testing.Short() {
		t.Skip("uses mDNS on the network; skipped with -short")
	}
	svc := uniqueCommissionableService()
	adv := NewMDNSAdvertiser()
	if err := adv.AdvertiseCommissionable(svc); err != nil {
		t.Skipf("the advertiser cannot publish here: %v", err)
	}
	defer adv.Withdraw()

	// The responder withdraws the service on a conflict found after it is
	// published, and calls the handler.
	published := commissionableLocalService(svc)
	if err := adv.server.Deregister(published); err != nil {
		t.Fatal(err)
	}
	adv.HandleConflict(&gomdns.ConflictError{Service: published, Name: published.FullName()})
	renamed, ok := adv.CommissionableInstanceName()
	if !ok || renamed == svc.InstanceName {
		t.Fatalf("published instance name = (%q, %v) after a conflict, want a new name", renamed, ok)
	}

	// A conflict of a service the advertiser did not publish is ignored.
	adv.HandleConflict(&gomdns.ConflictError{Service: otherNodeService("_http._tcp", "x", "y"), Name: "x._http._tcp.local"})
	if again, _ := adv.CommissionableInstanceName(); again != renamed {
		t.Errorf("published instance name = %q after an unrelated conflict, want %q", again, renamed)
	}

	// A host conflict withdraws the service without renaming it.
	current := commissionableLocalService(svc)
	current.Instance = renamed
	adv.HandleConflict(&gomdns.ConflictError{Service: current, Name: current.HostName()})
	if name, ok := adv.CommissionableInstanceName(); ok {
		t.Errorf("published instance name = %q after a host conflict, want none", name)
	}
}
