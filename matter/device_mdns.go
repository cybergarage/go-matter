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
	lookupIPv4AddrPort := func() (net.IP, int, error) {
		port, ok := dev.CommissionableNode.Port()
		if !ok {
			return nil, 0, fmt.Errorf("no port found for device: %s", dev.String())
		}

		addrs, ok := dev.CommissionableNode.Addresses()
		if !ok || len(addrs) == 0 {
			return nil, 0, fmt.Errorf("no addresses found for device: %s", dev.String())
		}
		for _, addr := range addrs {
			if ipv4 := addr.To4(); ipv4 != nil {
				return ipv4, port, nil
			}
		}
		return nil, 0, fmt.Errorf("no IPv4 address found for device: %s", dev.String())
	}

	addr, port, err := lookupIPv4AddrPort()
	if err != nil {
		return nil, err
	}

	remote := &net.UDPAddr{
		IP:   addr,
		Port: port,
		Zone: "",
	}

	conn, err := net.DialUDP("udp", nil, remote)
	if err != nil {
		return nil, err
	}

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add((DefaultCommissioningTimeout))
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
	var err error
	dev.conn, err = dev.openConn(ctx)
	if err != nil {
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
		return err
	}

	return nil
}

// String returns the string representation of the mDNS device.
func (dev *mDNSDevice) String() string {
	return dev.baseDevice.String(dev)
}

// MarshalObject returns an object suitable for marshaling to JSON.
func (dev *mDNSDevice) MarshalObject() any {
	return dev.baseDevice.MarshalObject(dev)
}
