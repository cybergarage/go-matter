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
	"math/big"
	"strings"
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
//
// Inputs:
//   - version:     Version of the onboarding payload format (1 bit, currently 0).
//   - vendorID:    Vendor ID (16 bits). For standard flow (11-digit code), set this to 0 to exclude it.
//   - productID:   Product ID (16 bits). For standard flow (11-digit code), set this to 0 to exclude it.
//   - discriminator:  Discriminator (12-bit device discriminator). The manual code will use the top 4 bits (the “short” discriminator).
//   - passcode:    Setup PIN code (passcode for PASE) up to 27 bits (typically an 8-digit decimal, but up to 2^27-1).
//
// Returns the manual pairing code as a numeric string. The code includes a Verhoeff checksum digit for error detection.
func encodeManualPairingCode(version uint8, vendorID uint16, productID uint16, discriminator uint16, passcode uint32) (string, error) {
	// Validate input ranges according to spec fields
	if version > 1 {
		return "", errors.New("version must be 0 or 1")
	}
	if discriminator > 0x0FFF {
		return "", errors.New("discriminator must be a 12-bit value (0-4095)")
	}
	if passcode > (1<<27)-1 {
		return "", errors.New("setup PIN code must be <= 27 bits (max 134217727)")
	}

	// Determine if we include VendorID/ProductID in the code.
	includeVendor := (vendorID != 0 || productID != 0)
	// Commissioning Flow: standard (0) if no vendor/product, otherwise non-standard (set to 1 for example).
	flow := uint8(0)
	if includeVendor {
		flow = 1 // use 1 or 2 for non-standard flows; both indicate vendor info included.
	}

	// Compute the numeric payload (without the checksum) as a big integer.
	// Use big.Int since the long code can exceed 64 bits (up to 66 bits of data).
	data := big.NewInt(0)
	if includeVendor {
		// Long code (21-digit): version(1 bit) | flow(2 bits) | VendorID(16 bits) | ProductID(16 bits) | shortDisc(4 bits) | PIN(27 bits)
		// Pack bits accordingly:
		// - Take the 4-bit "short discriminator" (top 4 bits of the 12-bit discriminator).
		shortDisc := uint64(discriminator>>8) & 0xF
		// Construct 66-bit value in a 64-bit intermediate (will not fully fit if version=1 and flow=2, but handle via big.Int if needed).
		// We'll shift each component into place using big.Int for safety.
		data.Or(data, big.NewInt(int64(passcode)&((1<<27)-1))) // bits 0-26: PIN
		data.Or(data, big.NewInt(int64(shortDisc)<<27))        // bits 27-30: discriminator (4 bits)
		data.Or(data, big.NewInt(int64(productID)&0xFFFF<<31)) // bits 31-46: ProductID (16 bits)
		data.Or(data, big.NewInt(int64(vendorID)&0xFFFF<<47))  // bits 47-62: VendorID (16 bits)
		data.Or(data, big.NewInt(int64(flow&0x3)<<63))         // bits 63-64: commissioning flow (2 bits)
		data.Or(data, big.NewInt(int64(version&0x1)<<65))      // bit 65: version (1 bit)
	} else {
		// Short code (11-digit): version(1 bit) | shortDisc(4 bits) | PIN(27 bits).
		// (For standard flow, CommissioningFlow=0 is assumed and not explicitly encoded to save space.)
		shortDisc := uint64(discriminator>>8) & 0xF
		data.Or(data, big.NewInt(int64(passcode)&((1<<27)-1))) // bits 0-26: PIN
		data.Or(data, big.NewInt(int64(shortDisc)<<27))        // bits 27-30: discriminator (4 bits)
		data.Or(data, big.NewInt(int64(version&0x1)<<31))      // bit 31: version (1 bit)
	}

	// Convert the data portion to a decimal string with leading zeros if necessary to fill the required length.
	var dataDec string
	if includeVendor {
		// Long code data should be 20 digits long (66-bit value fits in 20 decimal digits). Pad with leading zeros if needed.
		dataDec = data.Text(10)
		if len(dataDec) < 20 {
			dataDec = strings.Repeat("0", 20-len(dataDec)) + dataDec
		}
	} else {
		// Short code data should be 10 digits long (32-bit value fits in 10 decimal digits). Pad with leading zeros if needed.
		dataDec = data.Text(10)
		if len(dataDec) < 10 {
			dataDec = strings.Repeat("0", 10-len(dataDec)) + dataDec
		}
	}

	// Compute the Verhoeff checksum digit for the data portion.
	checkChar := generateVerhoeffCheck(dataDec)
	// Append the checksum digit to form the final code.
	code := dataDec + string(checkChar)

	return code, nil
}

// decodeManualPairingCode decodes an 11-digit or 21-digit manual pairing code string and returns the extracted fields.
// It returns: version, vendorID, productID, discriminator, passcode. For a short code (11-digit, standard flow), vendorID and productID will be 0 (not present).
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
	// Parse data portion into big.Int for bit extraction.
	dataInt, ok := new(big.Int).SetString(dataStr, 10)
	if !ok {
		return nil, errors.New("failed to parse numeric code")
	}

	// Determine if it's long or short code by length.
	isLong := (len(code) == 21)

	// Extract fields from the data bits.
	var version uint8
	var commFlow uint8
	var vendorID uint16
	var productID uint16
	var discriminator uint16
	var passcode uint32

	if isLong {
		// 20-digit data => 66-bit structure: version(1 bit)@65, flow(2 bits)@63-64, VendorID@47-62, ProductID@31-46, shortDisc@27-30, PIN@0-26.
		// Extract version (bit 65)
		versionInt := new(big.Int).Rsh(dataInt, 65)
		version = uint8(versionInt.Uint64() & 0x1)
		// Extract flow (bits 63-64)
		flowInt := new(big.Int).Rsh(dataInt, 63)
		commFlow = uint8(flowInt.Uint64() & 0x3)
		// Extract Vendor ID (16 bits at 47-62)
		vendorInt := new(big.Int).Rsh(dataInt, 47)
		vendorID = uint16(vendorInt.Uint64() & 0xFFFF)
		// Extract Product ID (16 bits at 31-46)
		productInt := new(big.Int).Rsh(dataInt, 31)
		productID = uint16(productInt.Uint64() & 0xFFFF)
		// Extract short discriminator (4 bits at 27-30)
		discInt := new(big.Int).Rsh(dataInt, 27)
		shortDisc := uint8(discInt.Uint64() & 0xF)
		// The manual code provides a 4-bit "short discriminator".
		// Reconstruct the full 12-bit discriminator by placing these 4 bits as the most significant bits and setting lower 8 bits to 0 (since they are not conveyed):contentReference[oaicite:14]{index=14}.
		discriminator = uint16(shortDisc) << 8
		// Extract PIN code (27 bits at 0-26)
		pinMask := big.NewInt(1)
		pinMask.Lsh(pinMask, 27).Sub(pinMask, big.NewInt(1)) // (1<<27) - 1
		pinInt := new(big.Int).And(dataInt, pinMask)
		passcode = uint32(pinInt.Uint64())
	} else {
		// 10-digit data => 32-bit structure: version(1 bit)@31, shortDisc(4 bits)@27-30, PIN@0-26.
		versionInt := new(big.Int).Rsh(dataInt, 31)
		version = uint8(versionInt.Uint64() & 0x1)
		commFlow = 0 // standard flow (not encoded in short code).
		vendorID = 0
		productID = 0
		discInt := new(big.Int).Rsh(dataInt, 27)
		shortDisc := uint8(discInt.Uint64() & 0xF)
		discriminator = uint16(shortDisc) << 8 // reconstruct 12-bit discriminator as shortDisc << 8 (low 8 bits assumed 0):contentReference[oaicite:16]{index=16}.
		pinMask := big.NewInt(1)
		pinMask.Lsh(pinMask, 27).Sub(pinMask, big.NewInt(1))
		pinInt := new(big.Int).And(dataInt, pinMask)
		passcode = uint32(pinInt.Uint64())
	}

	return &pairingCode{
		version:       version,
		vendorID:      vendorID,
		productID:     productID,
		commFlow:      commFlow,
		discriminator: discriminator,
		passcode:      passcode,
	}, nil
}
