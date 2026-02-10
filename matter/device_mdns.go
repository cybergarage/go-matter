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
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter/mdns"
	"github.com/cybergarage/go-matter/matter/pase"
	"github.com/cybergarage/go-matter/matter/types"
)

type mDNSDevice struct {
	*baseDevice
	mdns.CommissionableNode
	conn    *net.UDPConn
	readBuf []byte
}

func newMDNSDevice(node mdns.CommissionableNode) CommissionableDevice {
	return &mDNSDevice{
		baseDevice:         &baseDevice{},
		CommissionableNode: node,
		conn:               nil,
		readBuf:            make([]byte, 1500),
	}
}

// Type returns the device type.
func (dev *mDNSDevice) Type() DeviceType {
	return types.DNSDevice
}

// Address returns the device address.
func (dev *mDNSDevice) Address() string {
	addrs, ok := dev.CommissionableNode.Addresses()
	if !ok {
		return ""
	}
	addStrs := make([]string, len(addrs))
	for i, addr := range addrs {
		addStrs[i] = addr.String()
	}
	return strings.Join(addStrs, ",")
}

// VendorID represents a vendor ID.
// 2.5.2. Vendor Identifier (Vendor ID, VID).
func (dev *mDNSDevice) VendorID() VendorID {
	vid, ok := dev.CommissionableNode.VendorID()
	if !ok {
		return 0
	}
	return VendorID(vid)
}

// ProductID represents a product ID.
// 2.5.3. Product Identifier (Product ID, PID).
func (dev *mDNSDevice) ProductID() ProductID {
	pid, ok := dev.CommissionableNode.ProductID()
	if !ok {
		return 0
	}
	return ProductID(pid)
}

// Discriminator represents a discriminator.
// 2.5.6. Discriminator.
func (dev *mDNSDevice) Discriminator() Discriminator {
	discriminator, ok := dev.CommissionableNode.Discriminator()
	if !ok {
		return 0
	}
	return Discriminator(discriminator)
}

func (dev *mDNSDevice) openConn(ctx context.Context) (*net.UDPConn, error) {
	// lookupAddrPort looks up addresses preferring IPv6 link-local, then IPv4.
	// For IPv6 link-local addresses (fe80::/10), it attempts to determine the Zone
	// by checking available network interfaces.
	lookupAddrPort := func() (net.IP, int, string, error) {
		port, ok := dev.CommissionableNode.Port()
		if !ok {
			return nil, 0, "", fmt.Errorf("no port found for device: %s", dev.String())
		}

		addrs, ok := dev.CommissionableNode.Addresses()
		if !ok || len(addrs) == 0 {
			return nil, 0, "", fmt.Errorf("no addresses found for device: %s", dev.String())
		}

		// First pass: look for IPv6 link-local addresses (fe80::/10)
		for _, addr := range addrs {
			if addr.To4() == nil && addr.IsLinkLocalUnicast() {
				// IPv6 link-local requires a zone (interface) to be specified.
				// Try to find an interface that can reach this address by checking
				// which interfaces have link-local addresses in the same subnet.
				ifaces, err := net.Interfaces()
				if err == nil {
					for _, iface := range ifaces {
						// Skip down interfaces
						if iface.Flags&net.FlagUp == 0 {
							continue
						}
						// For link-local, use the first up interface with an IPv6 address
						// The OS routing will handle finding the correct path
						ifaceAddrs, err := iface.Addrs()
						if err != nil {
							continue
						}
						for _, ifaceAddr := range ifaceAddrs {
							ipNet, ok := ifaceAddr.(*net.IPNet)
							if !ok {
								continue
							}
							// If this interface has an IPv6 link-local address, use it
							if ipNet.IP.To4() == nil && ipNet.IP.IsLinkLocalUnicast() {
								log.Infof("Using IPv6 link-local address %s with zone %s", addr, iface.Name)
								return addr, port, iface.Name, nil
							}
						}
					}
				}
				// If we couldn't determine the interface, try using % notation or default
				// For many systems, the zone can be inferred by the OS
				log.Infof("Using IPv6 link-local address %s (zone detection failed, trying without zone)", addr)
				return addr, port, "", nil
			}
		}

		// Second pass: look for any IPv6 address
		for _, addr := range addrs {
			if addr.To4() == nil {
				log.Infof("Using IPv6 address %s", addr)
				return addr, port, "", nil
			}
		}

		// Third pass: fallback to IPv4
		for _, addr := range addrs {
			if ipv4 := addr.To4(); ipv4 != nil {
				log.Infof("Using IPv4 address %s", ipv4)
				return ipv4, port, "", nil
			}
		}

		return nil, 0, "", fmt.Errorf("no suitable address found for device: %s", dev.String())
	}

	addr, port, zone, err := lookupAddrPort()
	if err != nil {
		return nil, err
	}

	remote := &net.UDPAddr{
		IP:   addr,
		Port: port,
		Zone: zone,
	}

	conn, err := net.DialUDP("udp", nil, remote)
	if err != nil {
		return nil, err
	}

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(DefaultCommissioningTimeout)
	}

	if time.Now().After(deadline) {
		return nil, fmt.Errorf("context deadline exceeded: %s", deadline.String())
	}

	err = conn.SetWriteDeadline(deadline)
	if err != nil {
		return nil, err
	}
	err = conn.SetReadDeadline(deadline)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

// Transmit writes data to the transport.
func (dev *mDNSDevice) Transmit(ctx context.Context, b []byte) error {
	if dev.conn == nil {
		return fmt.Errorf("connection is not opened")
	}
	n, err := dev.conn.Write(b)
	if err != nil {
		return err
	}
	if n != len(b) {
		return fmt.Errorf("udp short write: %d/%d", n, len(b))
	}
	return nil
}

// Receive reads data from the transport.
func (dev *mDNSDevice) Receive(ctx context.Context) ([]byte, error) {
	if dev.conn == nil {
		return nil, fmt.Errorf("connection is not opened")
	}
	n, err := dev.conn.Read(dev.readBuf)
	if err != nil {
		return nil, err
	}
	return dev.readBuf[:n], nil
}

// Commission commissions the node with the given commissioning options.
func (dev *mDNSDevice) Commission(ctx context.Context, payload OnboardingPayload) error {
	log.Infof("Opening connection to mDNS device (%s)...", dev.String())

	var err error
	dev.conn, err = dev.openConn(ctx)
	if err != nil {
		log.Errorf("Failed to open connection to mDNS device (%s): %v", dev.String(), err)
		return err
	}
	defer func() {
		if err := dev.conn.Close(); err != nil {
			log.Error(err)
		}
		dev.conn = nil
	}()

	paseClient := pase.NewClient(dev, payload.Passcode())
	_, err = paseClient.EstablishSession(ctx)
	if err != nil {
		log.Errorf("Failed to establish PASE session with mDNS device (%s): %v", dev.String(), err)
		return err
	}

	return nil
}

// MatchesOnboardingPayload checks whether the device matches the given onboarding payload.
func (dev *mDNSDevice) MatchesOnboardingPayload(payload OnboardingPayload) bool {
	return dev.matchesOnboardingPayload(dev, payload)
}

// String returns the string representation of the mDNS device.
func (dev *mDNSDevice) String() string {
	return dev.baseDevice.string(dev)
}

// MarshalObject returns an object suitable for marshaling to JSON.
func (dev *mDNSDevice) MarshalObject() any {
	return dev.baseDevice.marshalObject(dev)
}
