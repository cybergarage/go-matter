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
func TestCryptoPA_Basic(t *testing.T) {
	passcode := []byte("testpasscode")
	salt := []byte("testsalt")
	iterations := 1000

	w0, w1, err := CryptoPAKEValuesInitiator(passcode, salt, iterations)
	if err != nil {
		t.Fatalf("CryptoPAKEValuesInitiator failed: %v", err)
	}

	pA, err := CryptoPA(w0, w1)
	if err != nil {
		t.Fatalf("CryptoPA failed: %v", err)
	}
	if len(pA) != CryptoPublicKeySizeBytes {
		t.Errorf("pA length = %d, want %d", len(pA), CryptoPublicKeySizeBytes)
	}
	if pA[0] != 0x04 {
		t.Errorf("pA prefix = 0x%02x, want 0x04", pA[0])
	}
}

func TestCryptoPA_InvalidInputLength(t *testing.T) {
	w0 := make([]byte, CryptoGroupSizeBytes-1)
	w1 := make([]byte, CryptoGroupSizeBytes)

	_, err := CryptoPA(w0, w1)
	if err == nil {
		t.Errorf("CryptoPA should fail with invalid w0 length")
	}
}

func TestCryptoPB_Basic(t *testing.T) {
	passcode := []byte("testpasscode")
	salt := []byte("testsalt")
	iterations := 1000

	w0, l, err := CryptoPAKEValuesResponder(passcode, salt, iterations)
	if err != nil {
		t.Fatalf("CryptoPAKEValuesResponder failed: %v", err)
	}

	pB, err := CryptoPB(w0, l)
	if err != nil {
		t.Fatalf("CryptoPB failed: %v", err)
	}
	if len(pB) != CryptoPublicKeySizeBytes {
		t.Errorf("pB length = %d, want %d", len(pB), CryptoPublicKeySizeBytes)
	}
	if pB[0] != 0x04 {
		t.Errorf("pB prefix = 0x%02x, want 0x04", pB[0])
	}
}

func TestCryptoPB_InvalidInputLength(t *testing.T) {
	w0 := make([]byte, CryptoGroupSizeBytes)
	l := make([]byte, CryptoPublicKeySizeBytes-1)

	_, err := CryptoPB(w0, l)
	if err == nil {
		t.Errorf("CryptoPB should fail with invalid l length")
	}
}

func TestCryptoTranscript_Basic(t *testing.T) {
	passcode := []byte("testpasscode")
	salt := []byte("testsalt")
	iter := 1000

	w0, w1, err := CryptoPAKEValuesInitiator(passcode, salt, iter)
	if err != nil {
		t.Fatalf("CryptoPAKEValuesInitiator failed: %v", err)
	}
	pA, err := CryptoPA(w0, w1)
	if err != nil {
		t.Fatalf("CryptoPA failed: %v", err)
	}
	_, l, err := CryptoPAKEValuesResponder(passcode, salt, iter)
	if err != nil {
		t.Fatalf("CryptoPAKEValuesResponder failed: %v", err)
	}
	pB, err := CryptoPB(w0, l)
	if err != nil {
		t.Fatalf("CryptoPB failed: %v", err)
	}

	// Use pA/pB as stand-in Z/V (valid-length curve points) for a basic test.
	Z := pA
	V := pB

	pbkdfReq := []byte("pbkdf-param-request")
	pbkdfResp := []byte("pbkdf-param-response")

	tt, err := CryptoTranscript(pbkdfReq, pbkdfResp, pA, pB, Z, V, w0)
	if err != nil {
		t.Fatalf("CryptoTranscript failed: %v", err)
	}
	if len(tt) == 0 {
		t.Fatal("CryptoTranscript returned empty TT")
	}

	// Different PBKDFParamRequest must produce a different TT.
	tt2, err := CryptoTranscript([]byte("other-req"), pbkdfResp, pA, pB, Z, V, w0)
	if err != nil {
		t.Fatalf("CryptoTranscript (tt2) failed: %v", err)
	}
	if bytes.Equal(tt, tt2) {
		t.Error("TT should differ when pbkdfParamRequest changes")
	}
}

func TestCryptoConfirmationValues_Basic(t *testing.T) {
	passcode := []byte("testpasscode")
	salt := []byte("testsalt")
	iter := 1000

	w0, w1, err := CryptoPAKEValuesInitiator(passcode, salt, iter)
	if err != nil {
		t.Fatalf("CryptoPAKEValuesInitiator failed: %v", err)
	}
	pA, err := CryptoPA(w0, w1)
	if err != nil {
		t.Fatalf("CryptoPA failed: %v", err)
	}
	_, l, err := CryptoPAKEValuesResponder(passcode, salt, iter)
	if err != nil {
		t.Fatalf("CryptoPAKEValuesResponder failed: %v", err)
	}
	pB, err := CryptoPB(w0, l)
	if err != nil {
		t.Fatalf("CryptoPB failed: %v", err)
	}

	tt, err := CryptoTranscript([]byte("pbkdf-param-request"), []byte("pbkdf-param-response"), pA, pB, pA, pB, w0)
	if err != nil {
		t.Fatalf("CryptoTranscript failed: %v", err)
	}

	cA, cB, ke, err := CryptoP2(tt, pA, pB)
	if err != nil {
		t.Fatalf("CryptoConfirmationValues failed: %v", err)
	}
	if len(cA) != CryptoHashLenBytes {
		t.Fatalf("cA length = %d, want %d", len(cA), CryptoHashLenBytes)
	}
	if len(cB) != CryptoHashLenBytes {
		t.Fatalf("cB length = %d, want %d", len(cB), CryptoHashLenBytes)
	}
	if len(ke) != CryptoHashLenBytes/2 {
		t.Fatalf("Ke length = %d, want %d", len(ke), CryptoHashLenBytes/2)
	}

	cA2, cB2, ke2, err := CryptoP2(tt, pA, pB)
	if err != nil {
		t.Fatalf("CryptoConfirmationValues second call failed: %v", err)
	}
	if !bytes.Equal(cA, cA2) || !bytes.Equal(cB, cB2) || !bytes.Equal(ke, ke2) {
		t.Fatal("confirmation values should be deterministic")
	}

	ttChanged, err := CryptoTranscript([]byte("other-request"), []byte("pbkdf-param-response"), pA, pB, pA, pB, w0)
	if err != nil {
		t.Fatalf("CryptoTranscript changed failed: %v", err)
	}
	cAChanged, cBChanged, _, err := CryptoP2(ttChanged, pA, pB)
	if err != nil {
		t.Fatalf("CryptoConfirmationValues changed failed: %v", err)
	}
	if bytes.Equal(cA, cAChanged) {
		t.Fatal("cA should change when TT changes")
	}
	if bytes.Equal(cB, cBChanged) {
		t.Fatal("cB should change when TT changes")
	}
}
