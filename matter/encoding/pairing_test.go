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

func TestPairingCode(t *testing.T) {
	tests := []struct {
		paringCode string
		expected   *pairingCode
	}{
		{
			// MT:Y.ET0EDB00SWDX0IA00
			paringCode: "3035-750-7966",
			expected: &pairingCode{
				version:   0,
				vendorID:  0,
				productID: 0,
				commFlow:  0,
				upperDesc: 3136 & 0x0F00,
				passcode:  13045239,
			},
		},
		{
			// MT:Y.ET08O614CCY06A810
			paringCode: "3572-993-5174",
			expected: &pairingCode{
				version:   0,
				vendorID:  0,
				productID: 0,
				commFlow:  0,
				upperDesc: 4068 & 0x0F00,
				passcode:  57630675,
			},
		},
		{
			// MT:5W124010006874
			paringCode: "2167-692-8175",
			expected: &pairingCode{
				version:   0,
				vendorID:  0,
				productID: 0,
				commFlow:  0,
				upperDesc: 2304 & 0x0F00,
				passcode:  46154113,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.paringCode, func(t *testing.T) {
			decodedCode, err := NewPairingCodeFromString(tt.paringCode)
			if err != nil {
				t.Errorf("Failed to decode pairing code %q: %v", tt.paringCode, err)
				return
			}
			if decodedCode.Version() != tt.expected.version {
				t.Errorf("Version(): got=%d, want=%d", decodedCode.Version(), tt.expected.version)
			}
			if decodedCode.VendorID() != tt.expected.vendorID {
				t.Errorf("VendorID(): got=%d, want=%d", decodedCode.VendorID(), tt.expected.vendorID)
			}
			if decodedCode.ProductID() != tt.expected.productID {
				t.Errorf("ProductID(): got=%d, want=%d", decodedCode.ProductID(), tt.expected.productID)
			}
			if decodedCode.CommissioningFlow() != CommissioningFlow(tt.expected.commFlow) {
				t.Errorf("CommFlow(): got=%d, want=%d", decodedCode.CommissioningFlow(), tt.expected.commFlow)
			}
			if !decodedCode.Discriminator().IsUpper4Bits() {
				t.Errorf("Discriminator(): expected upper 4 bits only, got=%d", decodedCode.Discriminator())
			}
			if decodedCode.Discriminator() != Discriminator(tt.expected.upperDesc) {
				t.Errorf("Discriminator(): got=%d, want=%d", decodedCode.Discriminator(), Discriminator(tt.expected.upperDesc))
			}
			if decodedCode.Passcode() != tt.expected.passcode {
				t.Errorf("Passcode(): got=%d, want=%d", decodedCode.Passcode(), tt.expected.passcode)
			}

			// Test String() method
			str := decodedCode.String()
			if str != tt.paringCode {
				t.Errorf("String(): got=%q, want=%q", str, tt.paringCode)
			}
		})
	}
}
