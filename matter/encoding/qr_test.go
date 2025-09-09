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

func TestQR(t *testing.T) {
	tests := []struct {
		payload QRCode
		qrCode  string
	}{
		{
			payload: QRCode{
				Version:               1,
				VendorID:              4572,
				ProductID:             997,
				CustomFlow:            0,
				DiscoveryCapabilities: 0,
				Discriminator:         0x01, // 12-bit discriminator = 0x001
				SetupPIN:              5174,
			},
			qrCode: "MT:-CM77NKT404C160ID00",
		},
	}

	for _, tt := range tests {
		got := tt.payload.String()
		if got != tt.qrCode {
			t.Errorf("QR = %q; want %q", got, tt.qrCode)
		}
	}
}
