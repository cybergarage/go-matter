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

	"github.com/cybergarage/go-matter/matter/encoding"
	"github.com/cybergarage/go-matter/matter/io"
	"github.com/cybergarage/go-matter/matter/types"
)

// Discriminator represents a discriminator.
type Discriminator = types.Discriminator

// OnboardingPayload represents an onboarding payload.
type OnboardingPayload = encoding.OnboardingPayload

// Device represents a device interface that is a piece of equipment containing one or more Nodes.
type Device interface {
	// VendorID represents a vendor ID.
	// 2.5.2. Vendor Identifier (Vendor ID, VID).
	VendorID() VendorID
	// ProductID represents a product ID.
	// 2.5.3. Product Identifier (Product ID, PID).
	ProductID() ProductID
	// Discriminator represents a discriminator.
	// 2.5.6. Discriminator.
	Discriminator() Discriminator
	// MarshalObject returns an object suitable for marshaling to JSON.
	MarshalObject() any
	// String returns the string representation of the device.
	String() string
}

// DeviceType represents a device type.
type DeviceType = types.DeviceType

// Transport represents a transport.
type Transport = io.Transport

// CommissionableDevice represents a commissionable device interface.
// 5.4.3. Discovery by Commissioner.
type CommissionableDevice interface {
	// Device returns the underlying device.
	Device
	// Transport returns the transport.
	Transport
	// Type returns the device type.
	Type() DeviceType
	// Address returns the device address.
	Address() string
	// Commission commissions the node with the given commissioning options.
	Commission(ctx context.Context, payload OnboardingPayload) error
	// CommissionableDeviceHelper represents a helper interface for commissionable devices.
	CommissionableDeviceHelper
}

// CommissionableDeviceHelper represents a helper interface for commissionable devices.
type CommissionableDeviceHelper interface {
	MatchesOnboardingPayload(payload OnboardingPayload) bool
}
