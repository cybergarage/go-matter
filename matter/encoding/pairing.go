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
	version       uint8
	vendorID      uint16
	productID     uint16
	commFlow      uint8
	discriminator uint16
	passcode      uint32
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
	return pc.discriminator
}

// Passcode returns the Passcode.
func (pc *pairingCode) Passcode() uint32 {
	return pc.passcode
}

// String returns the manual pairing code string representation (11-digit or 21-digit).
func (pc *pairingCode) String() string {
	// Generate the manual pairing code string (11-digit or 21-digit) based on the fields.
	code, err := encodeManualPairingCode(pc.version, pc.vendorID, pc.productID, pc.discriminator, pc.passcode)
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
// It supports both the 11-digit code (without Vendor ID/Product ID for standard commissioning flow) and the 21-digit code (including Vendor ID and Product ID for non-standard flows).
// Returns the manual pairing code as a numeric string. The code includes a Verhoeff checksum digit for error detection.
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
	d2 := (uint32)((discriminator&0x300)<<6) | (passcode & 0x3FFF)
	// DIGIT[7..10] :=(PASSCODE >> 14)
	d7 := (passcode >> 14) & 0x3FFF

	var dataDec string
	if !isLong {
		// 11  digits: d1(1) + d2(5) + d7(5)
		dataDec = fmt.Sprintf("%01d%05d%05d", d1, d2, d7)
	} else {
		// 21 digits: d1(1) + d2(5) + d7(4) + v(5) + p(5)
		dataDec = fmt.Sprintf("%01d%05d%04d%05d%05d", d1, d2, d7, vendorID, productID)
	}
	// Compute the Verhoeff checksum digit for the data portion.
	checkChar := generateVerhoeffCheck(dataDec)
	// Append the checksum digit to form the final code.
	code := dataDec + string(checkChar)

	return code, nil
}

// decodeManualPairingCode decodes an 11-digit or 21-digit manual pairing code string and returns the extracted fields.
func decodeManualPairingCode(code string) (*pairingCode, error) {
	// Remove any non-digit characters (e.g., spaces or hyphens) from the code.
	filtered := ""
	for _, r := range code {
		if unicode.IsDigit(r) {
			filtered += string(r)
		}
	}
	if filtered == "" {
		return nil, errors.New("code contains no digits")
	}
	code = filtered

	// Check length: must be 11 or 21 digits.
	if len(code) != 11 && len(code) != 21 {
		return nil, errors.New("manual pairing code must be 11 or 21 digits long")
	}
	// Verify the Verhoeff checksum of the entire code.
	if !validateVerhoeffCheck(code) {
		return nil, errors.New("manual pairing code failed checksum validation")
	}

	// Separate data portion (all but last digit) and the checksum.
	dataStr := code[:len(code)-1]

	// Determine if it's long or short code by length.
	isLong := (len(code) == 21)

	vpIdPresent := uint8(0)
	version := uint8(0)
	vendorID := uint16(0)
	productID := uint16(0)
	discriminator := uint16(0)
	passcode := uint32(0)

	// DIGIT[1] := (VID_PID_PRESENT << 2) |(DISCRIMINATOR >> 10)
	// DIGIT[2..6] :=((DISCRIMINATOR & 0x300)<< 6) |(PASSCODE & 0x3FFF)
	// DIGIT[2..6] :=((DISCRIMINATOR & 0x300)<< 6) |(PASSCODE & 0x3FFF)
	// DIGIT[7..10] :=(PASSCODE >> 14)

	if !isLong {
		d1, _ := strconv.Atoi(dataStr[0:1])
		d2_6, _ := strconv.Atoi(dataStr[1:6])
		d7_10, _ := strconv.Atoi(dataStr[6:10])

		vpIdPresent = uint8((d1 >> 2) & 0x1)
		discriminator = (uint16(d1) & 0x3) << 10
		discriminator |= uint16((d2_6 & 0xFC000) >> 14)
		passcode = uint32(d2_6 & 0x3FFF)
		passcode |= uint32(d7_10) << 14
	} else {
		d1, _ := strconv.Atoi(dataStr[0:1])
		d2_6, _ := strconv.Atoi(dataStr[1:6])
		d7_10, _ := strconv.Atoi(dataStr[6:10])
		v11_15, _ := strconv.Atoi(dataStr[10:15])
		p16_20, _ := strconv.Atoi(dataStr[15:20])

		discriminator = (uint16(d1) & 0x3) << 10
		discriminator |= uint16((d2_6 & 0xFC000) >> 14)
		passcode = uint32(d2_6 & 0x3FFF)
		passcode |= uint32(d7_10) << 14
		vendorID = uint16(v11_15)
		productID = uint16(p16_20)
	}

	commFlow := CommissioningFlowStandard
	if vpIdPresent == 1 {
		commFlow = CommissioningFlowCustom
	}

	return &pairingCode{
		version:       version,
		vendorID:      vendorID,
		productID:     productID,
		commFlow:      uint8(commFlow),
		discriminator: discriminator,
		passcode:      passcode,
	}, nil
}
