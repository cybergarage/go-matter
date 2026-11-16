// Copyright (C) 2026 The go-matter Authors. All rights reserved.
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

import "testing"

func TestValidatePasscode(t *testing.T) {
	for _, p := range []uint32{1, 20202021, 99999998, 34567890} {
		if err := ValidatePasscode(p); err != nil {
			t.Errorf("ValidatePasscode(%d) = %v", p, err)
		}
	}
	for _, p := range []uint32{0, 11111111, 22222222, 99999999, 12345678, 87654321, 100000000} {
		if err := ValidatePasscode(p); err == nil {
			t.Errorf("ValidatePasscode(%d) accepted", p)
		}
	}
}

// The codes made round-trip through their parsers.
func TestNewOnboardingCodes(t *testing.T) {
	const discriminator, passcode = 0xF00, 20202021
	manual, err := NewManualPairingCode(discriminator, passcode)
	if err != nil {
		t.Fatal(err)
	}
	// The manual code of the SDK's test device (discriminator 3840,
	// passcode 20202021).
	if got := manual.String(); got != "3497-011-2332" {
		t.Fatalf("manual code = %s, want 3497-011-2332", got)
	}
	parsed, err := NewPairingCodeFromString(manual.String())
	if err != nil || parsed.Passcode() != passcode || parsed.Discriminator() != 0xF00 {
		t.Fatalf("parsed manual code = %v, %v", parsed, err)
	}

	qr, err := NewQRPayload(0xFFF1, 0x8000, DiscoveryCapabilityOnNetwork, discriminator, passcode)
	if err != nil {
		t.Fatal(err)
	}
	back, err := NewQRPayloadFromString(qr.String())
	if err != nil {
		t.Fatal(err)
	}
	if back.VendorID() != 0xFFF1 || back.ProductID() != 0x8000 || back.Discriminator() != discriminator || back.Passcode() != passcode {
		t.Fatalf("parsed QR = %v/%v/%v/%v", back.VendorID(), back.ProductID(), back.Discriminator(), back.Passcode())
	}

	if _, err := NewManualPairingCode(0x1000, passcode); err == nil {
		t.Fatal("a 13-bit discriminator accepted")
	}
	if _, err := NewQRPayload(0, 0, 0, 1, 12345678); err == nil {
		t.Fatal("a trivial passcode accepted")
	}
}
