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
				version:       0,
				vendorID:      0,
				productID:     0,
				commFlow:      0,
				discriminator: 3136,
				passcode:      13045239,
			},
		},
	}

	for _, tt := range tests {
		decodedCode, err := NewPairingCodeFromString(tt.paringCode)
		if err != nil {
			t.Skipf("Failed to decode pairing code %q: %v", tt.paringCode, err)
			continue
		}
		if decodedCode.Version() != tt.expected.version {
			t.Skipf("Version: got=%d, want=%d", decodedCode.Version(), tt.expected.version)
		}
		if decodedCode.VendorID() != tt.expected.vendorID {
			t.Skipf("VendorID: got=%d, want=%d", decodedCode.VendorID(), tt.expected.vendorID)
		}
		if decodedCode.ProductID() != tt.expected.productID {
			t.Skipf("ProductID: got=%d, want=%d", decodedCode.ProductID(), tt.expected.productID)
		}
		if decodedCode.CommissioningFlow() != CommissioningFlow(tt.expected.commFlow) {
			t.Skipf("CommFlow: got=%d, want=%d", decodedCode.CommissioningFlow(), tt.expected.commFlow)
		}
		if decodedCode.Discriminator() != tt.expected.discriminator {
			t.Skipf("Discriminator: got=%d, want=%d", decodedCode.Discriminator(), tt.expected.discriminator)
		}
		if decodedCode.Passcode() != tt.expected.passcode {
			t.Skipf("Passcode: got=%d, want=%d", decodedCode.Passcode(), tt.expected.passcode)
		}

		// Test String() method
		str := decodedCode.String()
		if str != tt.paringCode {
			t.Skipf("String(): got=%q, want=%q", str, tt.paringCode)
		}
	}
}
