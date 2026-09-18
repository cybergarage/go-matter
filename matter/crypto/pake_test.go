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
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"io"
	"math/big"
	"testing"

	"golang.org/x/crypto/hkdf"
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

// TestCryptoPAKEValuesInitiatorMatchesSpecIndependentRecomputation guards
// against a regression where CryptoPAKEValuesInitiator/Responder requested
// only CryptoWSizeBytes (40) bytes of PBKDF2 output instead of the spec-
// mandated 2*CryptoWSizeBytes (80), and then split w0s/w1s at the 32-byte
// CryptoGroupSizeBytes boundary instead of the 40-byte CryptoWSizeBytes
// boundary. The resulting w0/w1 were the right length and internally
// consistent (so every length/inequality-only test above passed), but did
// not match spec 3.10's Crypto_PAKEValues_Initiator/_Responder, so they
// could never agree with a real device's SPAKE2+ computation — this was a
// root cause of persistent PASE "cB mismatch" failures against a real
// device even with a verified-correct passcode. This test recomputes w0s/
// w1s independently via crypto/pbkdf2 directly (not this package's
// CryptoPBKDF) with the correct length and split, so it can't share the bug.
func TestCryptoPAKEValuesInitiatorMatchesSpecIndependentRecomputation(t *testing.T) {
	passcode := []byte("testpasscode")
	salt := []byte("testsalt")
	iterations := 1000

	w0, w1, err := CryptoPAKEValuesInitiator(passcode, salt, iterations)
	if err != nil {
		t.Fatalf("CryptoPAKEValuesInitiator failed: %v", err)
	}

	ws, err := pbkdf2.Key(sha256.New, string(passcode), salt, iterations, 2*CryptoWSizeBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(ws) != 2*CryptoWSizeBytes {
		t.Fatalf("independent PBKDF2 output length = %d, want %d", len(ws), 2*CryptoWSizeBytes)
	}
	w0s := ws[:CryptoWSizeBytes]
	w1s := ws[CryptoWSizeBytes:]

	p := ellipticCurve.Params().P
	wantW0 := new(big.Int).Mod(new(big.Int).SetBytes(w0s), p).FillBytes(make([]byte, CryptoGroupSizeBytes))
	wantW1 := new(big.Int).Mod(new(big.Int).SetBytes(w1s), p).FillBytes(make([]byte, CryptoGroupSizeBytes))

	if !bytes.Equal(w0, wantW0) {
		t.Errorf("w0 = %x, want %x (independently recomputed per 3.10)", w0, wantW0)
	}
	if !bytes.Equal(w1, wantW1) {
		t.Errorf("w1 = %x, want %x (independently recomputed per 3.10)", w1, wantW1)
	}
}

func TestCryptoPA_Basic(t *testing.T) {
	passcode := []byte("testpasscode")
	salt := []byte("testsalt")
	iterations := 1000

	w0, _, err := CryptoPAKEValuesInitiator(passcode, salt, iterations)
	if err != nil {
		t.Fatalf("CryptoPAKEValuesInitiator failed: %v", err)
	}

	x, err := CryptoPAKERandomScalar()
	if err != nil {
		t.Fatalf("CryptoPAKERandomScalar failed: %v", err)
	}

	pA, err := CryptoPA(x, w0)
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
	x := make([]byte, CryptoGroupSizeBytes)

	_, err := CryptoPA(x, w0)
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
	x, err := CryptoPAKERandomScalar()
	if err != nil {
		t.Fatalf("CryptoPAKERandomScalar failed: %v", err)
	}
	pA, err := CryptoPA(x, w0)
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

	// Use proper Z/V derivation (use w1 to construct Z/V for test).
	Z, V, err := CryptoPAKESharedPoints(x, w0, w1, pB)
	if err != nil {
		t.Fatalf("CryptoPAKESharedPoints failed: %v", err)
	}

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
	x, err := CryptoPAKERandomScalar()
	if err != nil {
		t.Fatalf("CryptoPAKERandomScalar failed: %v", err)
	}
	pA, err := CryptoPA(x, w0)
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

	Z, V, err := CryptoPAKESharedPoints(x, w0, w1, pB)
	if err != nil {
		t.Fatalf("CryptoPAKESharedPoints failed: %v", err)
	}

	tt, err := CryptoTranscript([]byte("pbkdf-param-request"), []byte("pbkdf-param-response"), pA, pB, Z, V, w0)
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

	ttChanged, err := CryptoTranscript([]byte("other-request"), []byte("pbkdf-param-response"), pA, pB, Z, V, w0)
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

// TestCryptoP2MatchesSpecIndependentRecomputation guards against a regression
// where CryptoP2 skipped the Crypto_KDF(Ka, nil, "ConfirmationKeys", ...) step
// required by 3.10.4 and used Ka directly as the HMAC key for both cA and cB
// (instead of the distinct KcA/KcB it derives). That bug produced
// self-consistent, correctly-sized, deterministic output — so it passed every
// other test above — but did not interoperate with any spec-compliant
// responder (a real device would always compute a different cB). This test
// independently re-derives cA/cB using the standard library's hash/hmac/hkdf
// directly, rather than calling CryptoHash/CryptoHMAC/CryptoKDF, so it can't
// pass by sharing the same bug as the code under test.
func TestCryptoP2MatchesSpecIndependentRecomputation(t *testing.T) {
	tt := []byte("arbitrary transcript bytes for this test")
	// pA/pB must be valid P-256 points (CryptoP2 validates them); reuse the
	// fixed SPAKE2+ M/N generator points as stand-ins.
	pA := spake2pM
	pB := spake2pN

	cA, cB, ke, err := CryptoP2(tt, pA, pB)
	if err != nil {
		t.Fatalf("CryptoP2 failed: %v", err)
	}

	kaKe := sha256.Sum256(tt)
	half := len(kaKe) / 2
	wantKa := kaKe[:half]
	wantKe := kaKe[half:]

	kdf := hkdf.New(sha256.New, wantKa, nil, []byte("ConfirmationKeys"))
	kcAkcB := make([]byte, CryptoHashLenBytes)
	if _, err := io.ReadFull(kdf, kcAkcB); err != nil {
		t.Fatal(err)
	}
	wantKcA := kcAkcB[:half]
	wantKcB := kcAkcB[half:]

	wantCAMac := hmac.New(sha256.New, wantKcA)
	wantCAMac.Write(pB)
	wantCA := wantCAMac.Sum(nil)

	wantCBMac := hmac.New(sha256.New, wantKcB)
	wantCBMac.Write(pA)
	wantCB := wantCBMac.Sum(nil)

	if !bytes.Equal(cA, wantCA) {
		t.Errorf("cA = %x, want %x (independently recomputed per 3.10.4)", cA, wantCA)
	}
	if !bytes.Equal(cB, wantCB) {
		t.Errorf("cB = %x, want %x (independently recomputed per 3.10.4)", cB, wantCB)
	}
	if !bytes.Equal(ke, wantKe[:]) {
		t.Errorf("Ke = %x, want %x", ke, wantKe)
	}
}
