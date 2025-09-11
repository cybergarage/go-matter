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
	"fmt"
	"strings"
)

const (
	QRPayloadPrefix = "MT:"
)

// QRPayload represents the Matter QR code payload interface.
type QRPayload interface {
	// OnboardingPayload defines the common onboarding payload fields.
	OnboardingPayload
	// Bytes returns the QR code byte representation.
	Bytes() []byte
	// String encodes the payload into the Matter QR code string (with "MT:" prefix and Base38 encoding).
	String() string
}

// qrPayload represents the Matter QR code payload fields.
type qrPayload struct {
	version               uint8  // 3-bit version
	vendorID              uint16 // 16-bit Vendor ID
	productID             uint16 // 16-bit Product ID
	commFlow              uint8  // 2-bit commissioning flow (0=standard, 1=user-action, 2=custom)
	discoveryCapabilities uint8  // 8-bit discovery flags (bitmap for BLE, soft-AP, on-network, etc.)
	discriminator         uint16 // 12-bit discriminator (0–4095)
	passcode              uint32 // 27-bit setup PIN code (usually 8 decimal digits)
}

// NewQRPayloadFromString parses the QR code string and returns a QRPayload instance.
func NewQRPayloadFromString(str string) (QRPayload, error) {
	return newQRPayloadFromString(str)
}

func newQRPayloadFromString(str string) (*qrPayload, error) {
	if !strings.HasPrefix(str, QRPayloadPrefix) {
		return nil, fmt.Errorf("%w QR payload: %s", ErrInvalid, str)
	}
	encoded := strings.TrimPrefix(str, QRPayloadPrefix)
	payloadBytes, err := DecodeBase38(encoded)
	if err != nil {
		return nil, err
	}
	return newQRPayloadFromBytes(payloadBytes)
}

func newQRPayloadFromBytes(data []byte) (*qrPayload, error) {
	if len(data) != 11 {
		return nil, fmt.Errorf("%w QR payload length: %d", ErrInvalid, len(data))
	}
	bitPos := uint(0)

	// Helper to get bits from the buffer
	getBits := func(numBits uint) uint64 {
		var value uint64 = 0
		for i := range numBits {
			byteIndex := bitPos / 8
			bitIndex := bitPos % 8
			bit := (data[byteIndex] >> bitIndex) & 0x1
			value |= (uint64(bit) << i)
			bitPos++
		}
		return value
	}

	qr := &qrPayload{
		version:               uint8(getBits(3)),   // Version (3 bits)
		vendorID:              uint16(getBits(16)), // Vendor ID (16 bits):contentReference[oaicite:16]{index=16}
		productID:             uint16(getBits(16)), // Product ID (16 bits)
		commFlow:              uint8(getBits(2)),   // Custom Flow (2 bits)
		discoveryCapabilities: uint8(getBits(8)),   // Discovery capabilities (8 bits)
		discriminator:         uint16(getBits(12)), // Discriminator (12 bits)
		passcode:              uint32(getBits(27)), // Passcode (27 bits)
	}

	if (qr.passcode < 0x0000001) || (0x7FFFFFF < qr.passcode) {
		return nil, fmt.Errorf("%w QR payload passcode out of range: %d", ErrInvalid, qr.passcode)
	}

	return qr, nil
}

// Version returns the QR code version.
func (qr *qrPayload) Version() uint8 {
	return qr.version
}

// VendorID returns the Vendor ID.
func (qr *qrPayload) VendorID() uint16 {
	return qr.vendorID
}

// ProductID returns the Product ID.
func (qr *qrPayload) ProductID() uint16 {
	return qr.productID
}

// CommissioningFlow returns the Commissioning Flow.
func (qr *qrPayload) CommissioningFlow() CommissioningFlow {
	return CommissioningFlow(qr.commFlow)
}

// Discriminator returns the Discriminator.
func (qr *qrPayload) Discriminator() uint16 {
	return qr.discriminator
}

// Passcode returns the Passcode.
func (qr *qrPayload) Passcode() uint32 {
	return qr.passcode
}

// Bytes packs the payload fields into a little-endian []byte per Matter spec.
func (qr *qrPayload) Bytes() []byte {
	// Total bits = 3+16+16+2+8+12+27 + 4 padding = 88 bits (11 bytes):contentReference[oaicite:15]{index=15}
	totalBits := 88
	totalBytes := totalBits / 8 // 11 bytes
	buf := make([]byte, totalBytes)

	// Use a 64-bit or larger container (88 bits doesn't fit in 64-bit, so use bytes).
	// We'll pack bits LSB-first into a little-endian byte buffer.
	var bitPos uint = 0

	// Helper to set bits in the buffer
	setBits := func(value uint64, numBits uint) {
		for i := range numBits {
			// Determine if the i-th bit of value is 1
			bit := (value >> i) & 0x1
			// Set that bit at the current bitPos in the buffer
			byteIndex := bitPos / 8
			bitIndex := bitPos % 8
			if bit == 1 {
				buf[byteIndex] |= (1 << bitIndex)
			}
			bitPos++
		}
	}

	// Pack fields in LSB-first order:
	setBits(uint64(qr.version&0x7), 3)           // Version (3 bits)
	setBits(uint64(qr.vendorID), 16)             // Vendor ID (16 bits)
	setBits(uint64(qr.productID), 16)            // Product ID (16 bits)
	setBits(uint64(qr.commFlow&0x3), 2)          // Custom Flow (2 bits)
	setBits(uint64(qr.discoveryCapabilities), 8) // Discovery capabilities (8 bits)
	setBits(uint64(qr.discriminator&0xFFF), 12)  // Discriminator (12 bits)
	setBits(uint64(qr.passcode&0x7FFFFFF), 27)   // Passcode (27 bits)
	setBits(0, 4)                                // Padding (4 bits)
	// The remaining high-order bits (up to 88) serve as padding (implicitly 0).

	return buf
}

// String encodes the payload into the Matter QR code string (with "MT:" prefix and Base38 encoding).
func (qr *qrPayload) String() string {
	payloadBytes := qr.Bytes()
	qrEncoded := EncodeBase38(payloadBytes)
	return "MT:" + qrEncoded
}
