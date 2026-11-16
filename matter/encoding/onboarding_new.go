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

package encoding

import (
	"fmt"

	"github.com/cybergarage/go-matter/matter/types"
)

// DiscoveryCapabilityOnNetwork is the discovery capability of a device
// found on its IP network: the only one of a commissioning window opened by
// an administrator. 5.1.1.3. Discovery Capabilities Bitmask.
const DiscoveryCapabilityOnNetwork uint8 = 0x04

// maxDiscriminator is the largest 12-bit discriminator. 5.1.1.5.
const maxDiscriminator = 0x0FFF

// ValidatePasscode reports whether passcode may be a setup passcode: from 1
// to 99999998, and none of the trivial values 11111111, 22222222, …,
// 99999999, 12345678 and 87654321 (00000000 is out of range already).
// 5.1.7.1. Invalid Passcodes.
func ValidatePasscode(passcode uint32) error {
	if passcode < 1 || 99999998 < passcode {
		return fmt.Errorf("%w passcode: %d is out of 1..99999998", ErrInvalid, passcode)
	}
	if passcode%11111111 == 0 || passcode == 12345678 || passcode == 87654321 {
		return fmt.Errorf("%w passcode: %08d is not allowed", ErrInvalid, passcode)
	}
	return nil
}

// NewManualPairingCode returns the 11-digit manual pairing code of the
// standard commissioning flow for discriminator and passcode: the code
// carries the upper 4 bits of the discriminator only. 5.1.4. Manual
// Pairing Code.
func NewManualPairingCode(discriminator uint16, passcode uint32) (PairingCode, error) {
	if maxDiscriminator < discriminator {
		return nil, fmt.Errorf("%w discriminator: %d is out of 0..%d", ErrInvalid, discriminator, maxDiscriminator)
	}
	if err := ValidatePasscode(passcode); err != nil {
		return nil, err
	}
	return &pairingCode{
		version:   0,
		vendorID:  0,
		productID: 0,
		commFlow:  uint8(types.CommissioningFlowStandard),
		upperDesc: discriminator & 0x0F00,
		passcode:  passcode,
	}, nil
}

// NewQRPayload returns the QR code payload of the standard commissioning
// flow with the given fields. 5.1.3. QR Code.
func NewQRPayload(vendorID uint16, productID uint16, discoveryCapabilities uint8, discriminator uint16, passcode uint32) (QRPayload, error) {
	if maxDiscriminator < discriminator {
		return nil, fmt.Errorf("%w discriminator: %d is out of 0..%d", ErrInvalid, discriminator, maxDiscriminator)
	}
	if err := ValidatePasscode(passcode); err != nil {
		return nil, err
	}
	return &qrPayload{
		version:               0,
		vendorID:              vendorID,
		productID:             productID,
		commFlow:              uint8(types.CommissioningFlowStandard),
		discoveryCapabilities: discoveryCapabilities,
		discriminator:         discriminator,
		passcode:              passcode,
	}, nil
}
