// Copyright (C) 2024 The go-matter Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain the copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mdns

import (
	"github.com/cybergarage/go-matter/matter/types"
)

// VendorID represents a vendor ID.
type VendorID = types.VendorID

// Discriminator represents the discriminator value used in onboarding payloads.
type Discriminator = types.Discriminator

// CommissionableNode represents the commissionable node.
type CommissionableNode interface {
	// VendorID returns the vendor ID from the TXT record if available; otherwise, it returns the vendor ID from the subtype.
	// 4.3.1.3. Commissioning Subtypes (_V)
	// 4.3.1.6. TXT key for Vendor ID and Product ID (VP)
	VendorID() (VendorID, bool)
	// ProductID returns the vendor and product ID from the TXT record if available.
	// 4.3.1.6. TXT key for Vendor ID and Product ID (VP)
	ProductID() (string, bool)
	// ShortDiscriminator returns the short 4-bit discriminator from the subtype if available.
	// 4.3.1.3. Commissioning Subtypes (_S)
	ShortDiscriminator() (Discriminator, bool)
	// FullDiscriminator returns the full 12-bit discriminator from the TXT record if available; otherwise, it returns the full 12-bit discriminator from the subtype.
	// 4.3.1.3. Commissioning Subtypes (_L)
	// 4.3.1.5. TXT key for discriminator (D)
	FullDiscriminator() (Discriminator, bool)
	// Discriminator returns the full 12-bit discriminator from the TXT record if available; otherwise, it returns the full 12-bit or short 4-bit discriminator from the subtype.
	// 4.3.1.3. Commissioning Subtypes (_L,_S)
	// 4.3.1.5. TXT key for discriminator (D)
	Discriminator() (Discriminator, bool)
	// CommissioningMode returns the commissioning mode from the TXT record if available; otherwise, it returns the commissioning mode from the subtype if available.
	// 4.3.1.3. Commissioning Subtypes (_CM)
	// 4.3.1.7. TXT key for commissioning mode (CM)
	CommissioningMode() (CommissioningMode, bool)
	// DeviceType returns the device type from the TXT record if available; otherwise, it returns the device type from the subtype.
	// 4.3.1.3. Commissioning Subtypes (_T)
	// 4.3.1.8. TXT key for device type (DT)
	DeviceType() (DeviceType, bool)
	// DeviceName returns the device name from the TXT record if available,
	// 4.3.1.9. TXT key for device name (DN)
	DeviceName() (string, bool)
	// RotatingDeviceID returns the rotating device identifier from the TXT record if available,
	// 4.3.1.10. TXT key for rotating device identifier (RI)
	RotatingDeviceID() (string, bool)
	// PairingHint returns the pairing hint from the TXT record if available,
	// 4.3.1.11. TXT key for pairing hint (PH)
	PairingHint() (PairingHint, bool)
	// PairingInstructions returns the pairing instructions from the TXT record if available,
	// 4.3.1.12. TXT key for pairing instructions (PI)
	PairingInstructions() (string, bool)
	// String returns the string representation.
	String() string
}
