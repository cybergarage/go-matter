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
		expected  QRPayload
	}{
		{
			qrPayload: "MT:Y.ET08O614CCY06A810",
			expected: QRPayload{ // nolint:exhaustruct
				Version:       1,
				VendorID:      37395,
				ProductID:     769,
				CustomFlow:    0,
				Discriminator: 1039,
				Passcode:      5174,
			},
		},
		{
			qrPayload: "",
			expected: QRPayload{ // nolint:exhaustruct
				Version:       1,
				VendorID:      37395,
				ProductID:     259,
				CustomFlow:    0,
				Discriminator: 3083,
				Passcode:      1082,
			},
		},
	}

	for _, tt := range tests {
		if tt.qrPayload == "" {
			continue
		}
		got, err := NewQRPayloadFromString(tt.qrPayload)
		if err != nil {
			t.Errorf("NewQRPayloadFromString(%q) = %v", tt.qrPayload, err)
			continue
		}
		t.Logf("QRPayload: %+v", got)
	}
}
