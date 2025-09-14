// Copyright (C) 2025 The go-matter Authors. All rights reserved.
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
	"errors"
	"fmt"
	"strconv"
	"unicode"
)

// PairingCode represents a Matter manual pairing code.
type PairingCode interface {
	// OnboardingPayload defines the common onboarding payload fields.
	OnboardingPayload
	// String returns the manual pairing code string representation (11-digit or 21-digit).
	String() string
}

type pairingCode struct {
	version   uint8
	vendorID  uint16
	productID uint16
	commFlow  uint8
	shortDesc uint16
	passcode  uint32
}

// NewPairingCodeFromString decodes a manual pairing code string and returns a PairingCode instance.
func NewPairingCodeFromString(code string) (PairingCode, error) {
	return decodeManualPairingCode(code)
}

// Version returns the version.
func (pc *pairingCode) Version() uint8 {
	return pc.version
}

// VendorID returns the Vendor ID.
func (pc *pairingCode) VendorID() uint16 {
	return pc.vendorID
}

// ProductID returns the Product ID.
func (pc *pairingCode) ProductID() uint16 {
	return pc.productID
}

// CommissioningFlow returns the Commissioning Flow.
func (pc *pairingCode) CommissioningFlow() CommissioningFlow {
	return CommissioningFlow(pc.commFlow)
}

// Discriminator returns the Discriminator.
func (pc *pairingCode) Discriminator() uint16 {
	return pc.shortDesc
}

// Passcode returns the Passcode.
func (pc *pairingCode) Passcode() uint32 {
	return pc.passcode
}

// String returns the manual pairing code string representation (11-digit or 21-digit).
func (pc *pairingCode) String() string {
	// Generate the manual pairing code string (11-digit or 21-digit) based on the fields.
	code, err := encodeManualPairingCode(pc.version, pc.vendorID, pc.productID, pc.shortDesc, pc.passcode)
	if err != nil {
		return ""
	}
	switch len(code) {
	case 11:
		// Format as "XXXX-XXX-XXXX"
		return code[:4] + "-" + code[4:7] + "-" + code[7:]
	case 21:
		// Format as "XXXX-XXX-XXXX-XXXX-XXX-XX-X"
		return code[:4] + "-" + code[4:7] + "-" + code[7:11] + "-" + code[11:15] + "-" + code[15:17] + "-" + code[17:]
	}
	return code
}

// encodeManualPairingCode generates the manual pairing code (as a numeric string) based on Matter 1.4 specification.
func encodeManualPairingCode(version uint8, vendorID uint16, productID uint16, discriminator uint16, passcode uint32) (string, error) {
	// Determine if we include VendorID/ProductID in the code.
	isLong := (vendorID != 0 || productID != 0)
	vpIdPresent := uint16(0)
	if isLong {
		vpIdPresent = 1
	}

	// DIGIT[1] := (VID_PID_PRESENT << 2) |(DISCRIMINATOR >> 10)
	d1 := (vpIdPresent << 2) | uint16((discriminator>>10)&0x3)
	// DIGIT[2..6] :=((DISCRIMINATOR & 0x300)<< 6) |(PASSCODE & 0x3FFF)
	d2_6 := (uint32)((discriminator&0x300)<<6) | (passcode & 0x3FFF)
	// DIGIT[7..10] :=(PASSCODE >> 14)
	d7_10 := (passcode >> 14) & 0x3FFF

	var code string
	if !isLong {
		// 11  digits: d1(1) + d2(5) + d7(4)
		code = fmt.Sprintf("%01d%05d%04d", d1, d2_6, d7_10)
	} else {
		// 21 digits: d1(1) + d2(5) + d7(4) + v(5) + p(5)
		code = fmt.Sprintf("%01d%05d%04d%05d%05d", d1, d2_6, d7_10, vendorID, productID)
	}
	// Compute the Verhoeff checksum digit for the data portion.
	checkChar := generateVerhoeffCheck(code)

	// Append the checksum digit to form the final code.
	return code + string(checkChar), nil
}

// decodeManualPairingCode decodes an 11-digit or 21-digit manual pairing code string and returns the extracted fields.
func decodeManualPairingCode(paraingCodeStr string) (*pairingCode, error) {
	// Remove any non-digit characters (e.g., spaces or hyphens) from the c.
	code := ""
	for _, r := range paraingCodeStr {
		if unicode.IsDigit(r) {
			code += string(r)
		}
	}

	// Verify the Verhoeff checksum of the entire code.
	if !validateVerhoeffCheck(code) {
		return nil, errors.New("manual pairing code failed checksum validation")
	}

	// Check length: must be 11 or 21 digits.
	if len(code) != 11 && len(code) != 21 {
		return nil, errors.New("manual pairing code must be 11 or 21 digits long")
	}

	// Determine if VendorID/ProductID are included based on length.
	isLong := (len(code) == 21)

	// DIGIT[1] := (VID_PID_PRESENT << 2) |(DISCRIMINATOR >> 10)
	// DIGIT[2..6] :=((DISCRIMINATOR & 0x300)<< 6) |(PASSCODE & 0x3FFF)
	// DIGIT[7..10] :=(PASSCODE >> 14)

	d1, _ := strconv.Atoi(code[0:1])
	d2_6, _ := strconv.Atoi(code[1:6])
	d7_10, _ := strconv.Atoi(code[6:10])

	version := uint8(0)
	vpIdPresent := uint8((d1 >> 2) & 0x1)

	// 5.1.1.5. Discriminator value
	// For machine-readable formats, the full 12-bit Discriminator is used. For the Manual Pairing Code,
	// only the upper 4 bits out of the 12-bit Discriminator are used.
	discUpper := (uint16(d1&0x03) << 10)
	discLower := uint16((d2_6 & 0xC000) >> 6)
	disc := discUpper | discLower

	passLower := uint32(d2_6 & 0x3FFF)
	passUpper := uint32(d7_10) << 14
	passcode := passUpper | passLower

	vendorID := uint16(0)
	productID := uint16(0)

	if isLong {
		// DIGIT[11..15] := (VENDOR_ID)
		// DIGIT[16..20] := (PRODUCT_ID)

		v11_15, _ := strconv.Atoi(code[10:15])
		p16_20, _ := strconv.Atoi(code[15:20])
		vendorID = uint16(v11_15)
		productID = uint16(p16_20)
	}

	commFlow := CommissioningFlowStandard
	if vpIdPresent == 1 {
		commFlow = CommissioningFlowCustom
	}

	return &pairingCode{
		version:   version,
		vendorID:  vendorID,
		productID: productID,
		commFlow:  uint8(commFlow),
		shortDesc: disc,
		passcode:  passcode,
	}, nil
}
