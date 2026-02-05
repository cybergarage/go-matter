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
	"strings"

	"github.com/cybergarage/go-matter/matter/mdns"
	"github.com/cybergarage/go-matter/matter/types"
)

type mDNSDevice struct {
	*baseDevice
	mdns.CommissionableNode
}

func newMDNSDevice(node mdns.CommissionableNode) CommissionableDevice {
	return &mDNSDevice{
		baseDevice:         &baseDevice{},
		CommissionableNode: node,
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

// Commission commissions the node with the given commissioning options.
func (dev *mDNSDevice) Commission(ctx context.Context, payload OnboardingPayload) error {
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
