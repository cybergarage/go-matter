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
		qrPayload string
		expected  *qrPayload
	}{
		{
			qrPayload: "MT:Y.ET0EDB00SWDX0IA00",
			expected: &qrPayload{ // nolint:exhaustruct
				version:       0,
				vendorID:      5010,
				productID:     259,
				customFlow:    0,
				discriminator: 3136,
				passcode:      13045239,
			},
		},
		{
			qrPayload: "MT:Y.ET08O614CCY06A810",
			expected: &qrPayload{ // nolint:exhaustruct
				version:       0,
				vendorID:      5010,
				productID:     259,
				customFlow:    0,
				discriminator: 4068,
				passcode:      57630675,
			},
		},
		{
			qrPayload: "MT:MFAA0CIW17MA.X1IN00",
			expected: &qrPayload{ // nolint:exhaustruct
				version:       0,
				vendorID:      4933,
				productID:     40961,
				customFlow:    0,
				discriminator: 1399,
				passcode:      29236770,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.qrPayload, func(t *testing.T) {
			got, err := NewQRPayloadFromString(tt.qrPayload)
			if err != nil {
				t.Errorf("NewQRPayloadFromString(%q) = %v", tt.qrPayload, err)
				return
			}
			if got.Version() != tt.expected.version {
				t.Errorf("Version: got=%d, want=%d", got.Version(), tt.expected.version)
			}
			if got.VendorID() != tt.expected.vendorID {
				t.Errorf("VendorID: got=%d, want=%d", got.VendorID(), tt.expected.vendorID)
			}
			if got.ProductID() != tt.expected.productID {
				t.Errorf("ProductID: got=%d, want=%d", got.ProductID(), tt.expected.productID)
			}
			if got.CustomFlow() != tt.expected.customFlow {
				t.Errorf("CustomFlow: got=%d, want=%d", got.CustomFlow(), tt.expected.customFlow)
			}
			if got.Discriminator() != tt.expected.discriminator {
				t.Errorf("Discriminator: got=%d, want=%d", got.Discriminator(), tt.expected.discriminator)
			}
			if got.Passcode() != tt.expected.passcode {
				t.Errorf("Passcode: got=%d, want=%d", got.Passcode(), tt.expected.passcode)
			}
		})
	}
}
