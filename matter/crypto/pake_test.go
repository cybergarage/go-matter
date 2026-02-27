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

package crypto

import (
	"bytes"
	"testing"
)

func TestCryptoPAKEValuesInitiator_Basic(t *testing.T) {
	passcode := []byte("testpasscode")
	salt := []byte("testsalt")
	iterations := 1000

	w0, w1, err := CryptoPAKEValuesInitiator(passcode, salt, iterations)
	if err != nil {
		t.Fatalf("CryptoPAKEValuesInitiator failed: %v", err)
	}
	if len(w0) != CryptoGroupSizeBytes {
		t.Errorf("w0 length = %d, want %d", len(w0), CryptoGroupSizeBytes)
	}
	if len(w1) != CryptoGroupSizeBytes {
		t.Errorf("w1 length = %d, want %d", len(w1), CryptoGroupSizeBytes)
	}
	if bytes.Equal(w0, w1) {
		t.Errorf("w0 and w1 should not be equal")
	}
}
func TestCryptoPAKEValuesResponder_Basic(t *testing.T) {
	passcode := []byte("testpasscode")
	salt := []byte("testsalt")
	iterations := 1000

	w0, l, err := CryptoPAKEValuesResponder(passcode, salt, iterations)
	if err != nil {
		t.Fatalf("CryptoPAKEValuesResponder failed: %v", err)
	}
	if len(w0) != CryptoGroupSizeBytes {
		t.Errorf("w0 length = %d, want %d", len(w0), CryptoGroupSizeBytes)
	}
	if len(l) != CryptoPublicKeySizeBytes {
		t.Errorf("l length = %d, want %d", len(l), CryptoPublicKeySizeBytes)
	}
	if bytes.Equal(w0, l) {
		t.Errorf("w0 and l should not be equal")
	}
}
