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

	"github.com/cybergarage/go-matter/matter/mdns"
)

type mDNSDevice struct {
	mdns.CommissionableNode
}

func newMDNSDevice(node mdns.CommissionableNode) CommissionableDevice {
	return &mDNSDevice{
		CommissionableNode: node,
	}
}

// VendorID represents a vendor ID.
// 2.5.2. Vendor Identifier (Vendor ID, VID).
func (d *mDNSDevice) VendorID() VendorID {
	vid, ok := d.CommissionableNode.VendorID()
	if !ok {
		return 0
	}
	return VendorID(vid)
}

// ProductID represents a product ID.
// 2.5.3. Product Identifier (Product ID, PID).
func (d *mDNSDevice) ProductID() ProductID {
	pid, ok := d.CommissionableNode.ProductID()
	if !ok {
		return 0
	}
	return ProductID(pid)
}

// Discriminator represents a discriminator.
// 2.5.6. Discriminator.
func (d *mDNSDevice) Discriminator() Discriminator {
	discriminator, ok := d.CommissionableNode.Discriminator()
	if !ok {
		return 0
	}
	return Discriminator(discriminator)
}

// Commission commissions the node with the given commissioning options.
func (d *mDNSDevice) Commission(ctx context.Context, payload OnboardingPayload) error {
	return nil
}
