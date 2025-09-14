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
	"testing"
)

func TestQRPayload(t *testing.T) {
	tests := []struct {
		payloadString string
		expected      *qrPayload
	}{
		{
			payloadString: "MT:Y.ET0EDB00SWDX0IA00",
			expected: &qrPayload{ // nolint:exhaustruct
				version:       0,
				vendorID:      5010,
				productID:     259,
				commFlow:      0,
				discriminator: 3136,
				passcode:      13045239,
			},
		},
		{
			payloadString: "MT:Y.ET08O614CCY06A810",
			expected: &qrPayload{ // nolint:exhaustruct
				version:       0,
				vendorID:      5010,
				productID:     259,
				commFlow:      0,
				discriminator: 4068,
				passcode:      57630675,
			},
		},
		{
			payloadString: "MT:MFAA0CIW17MA.X1IN00",
			expected: &qrPayload{ // nolint:exhaustruct
				version:       0,
				vendorID:      4933,
				productID:     40961,
				commFlow:      0,
				discriminator: 1399,
				passcode:      29236770,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.payloadString, func(t *testing.T) {
			decodedPayload, err := NewQRPayloadFromString(tt.payloadString)
			if err != nil {
				t.Errorf("NewQRPayloadFromString(%q) = %v", tt.payloadString, err)
				return
			}
			if decodedPayload.Version() != tt.expected.version {
				t.Errorf("Version: got=%d, want=%d", decodedPayload.Version(), tt.expected.version)
			}
			if decodedPayload.VendorID() != tt.expected.vendorID {
				t.Errorf("VendorID: got=%d, want=%d", decodedPayload.VendorID(), tt.expected.vendorID)
			}
			if decodedPayload.ProductID() != tt.expected.productID {
				t.Errorf("ProductID: got=%d, want=%d", decodedPayload.ProductID(), tt.expected.productID)
			}
			if decodedPayload.CommissioningFlow() != CommissioningFlow(tt.expected.commFlow) {
				t.Errorf("CommissioningFlow: got=%d, want=%d", decodedPayload.CommissioningFlow(), tt.expected.commFlow)
			}
			if !decodedPayload.Discriminator().IsFull12Bits() {
				t.Errorf("Discriminator: expected full 12 bits, got=%d", decodedPayload.Discriminator())
			}
			if decodedPayload.Discriminator() != Discriminator(tt.expected.discriminator) {
				t.Errorf("Discriminator: got=%d, want=%d", decodedPayload.Discriminator(), Discriminator(tt.expected.discriminator))
			}
			if decodedPayload.Passcode() != tt.expected.passcode {
				t.Errorf("Passcode: got=%d, want=%d", decodedPayload.Passcode(), tt.expected.passcode)
			}

			encodedPayloadString := decodedPayload.String()
			if encodedPayloadString != tt.payloadString {
				t.Errorf("String: got=%q, want=%q", encodedPayloadString, tt.payloadString)
			}
		})
	}
}
