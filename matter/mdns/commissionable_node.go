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

package mdns

import (
	_ "embed"
)

// CommissionableNode represents a commissionable node.
type CommissionableNode interface {
	// VendorID returns a vendor and product ID.
	// 4.3.1.3. Commissioning Subtypes (_V)
	// 4.3.1.6. TXT key for Vendor ID and Product ID (VP)
	VendorID() (string, bool)
	// ProductID returns a vendor and product ID.
	// 4.3.1.6. TXT key for Vendor ID and Product ID (VP)
	ProductID() (string, bool)
	// ShortDiscriminator returns a short 4-bit discriminator.
	// 4.3.1.3. Commissioning Subtypes (_S)
	ShortDiscriminator() (string, bool)
	// LookupDiscriminator returns a full 12-bit discriminator.
	// 4.3.1.3. Commissioning Subtypes (_L)
	FullDiscriminator() (string, bool)
	// Discriminator returns a full discriminator or short discriminator.
	// 4.3.1.3. Commissioning Subtypes (_L,_S)
	// 4.3.1.5. TXT key for discriminator (D)
	Discriminator() (string, bool)
	// CommissioningMode returns a commissioning mode.
	// 4.3.1.3. Commissioning Subtypes (_CM)
	// 4.3.1.7. TXT key for commissioning mode (CM)
	CommissioningMode() (string, bool)
	// DeviceType returns a device type.
	// 4.3.1.3. Commissioning Subtypes (_T)
	// 4.3.1.8. TXT key for device type (DT)
	DeviceType() (DeviceType, bool)
	// DeviceName returns a device name.
	// 4.3.1.9. TXT key for device name (DN)
	DeviceName() (string, bool)
	// RotatingDeviceID returns a rotating device identifier.
	// 4.3.1.10. TXT key for rotating device identifier (RI)
	RotatingDeviceID() (string, bool)
	// PairingHint returns a pairing hint.
	// 4.3.1.11. TXT key for pairing hint (PH)
	PairingHint() (PairingHint, bool)
	// PairingInstructions returns a pairing instructions.
	// 4.3.1.12. TXT key for pairing instructions (PI)
	PairingInstructions() (string, bool)
}
