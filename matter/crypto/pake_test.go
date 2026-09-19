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
	"crypto/elliptic"
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

	// w0/w1 are EC scalars, reduced modulo the group order N (not the field
	// prime P used to reduce point coordinates) — see cryptoPAKEModP's doc.
	order := ellipticCurve.Params().N
	wantW0 := new(big.Int).Mod(new(big.Int).SetBytes(w0s), order).FillBytes(make([]byte, CryptoGroupSizeBytes))
	wantW1 := new(big.Int).Mod(new(big.Int).SetBytes(w1s), order).FillBytes(make([]byte, CryptoGroupSizeBytes))

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

	w0, _, err := CryptoPAKEValuesResponder(passcode, salt, iterations)
	if err != nil {
		t.Fatalf("CryptoPAKEValuesResponder failed: %v", err)
	}
	y, err := CryptoPAKERandomScalar()
	if err != nil {
		t.Fatalf("CryptoPAKERandomScalar failed: %v", err)
	}

	pB, err := CryptoPB(y, w0)
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
	y := make([]byte, CryptoGroupSizeBytes)
	w0 := make([]byte, CryptoGroupSizeBytes-1)

	_, err := CryptoPB(y, w0)
	if err == nil {
		t.Errorf("CryptoPB should fail with invalid w0 length")
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
	y, err := CryptoPAKERandomScalar()
	if err != nil {
		t.Fatalf("CryptoPAKERandomScalar failed: %v", err)
	}
	pB, err := CryptoPB(y, w0)
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
	y, err := CryptoPAKERandomScalar()
	if err != nil {
		t.Fatalf("CryptoPAKERandomScalar failed: %v", err)
	}
	pB, err := CryptoPB(y, w0)
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
	if !bytes.Equal(ke, wantKe) {
		t.Errorf("Ke = %x, want %x", ke, wantKe)
	}
}

// TestCryptoPBMatchesSpecIndependentRecomputation guards against the exact
// regression fixed in CryptoPB: it used to return L (w1*P, fixed by the
// passcode alone) as pB, never generating or using an ephemeral y, or
// computing y*P + w0*N at all. That produced a correctly shaped,
// deterministic 65-byte point — passing every shape/length check — but a
// spec-compliant initiator would derive Z/V (and thus session keys) that
// never match, since pB itself never varied per session. This test
// independently recomputes y*P + w0*N via raw crypto/elliptic calls, not by
// calling CryptoPB a second time.
func TestCryptoPBMatchesSpecIndependentRecomputation(t *testing.T) {
	passcode := []byte("testpasscode")
	salt := []byte("testsalt")
	iterations := 1000

	w0, _, err := CryptoPAKEValuesResponder(passcode, salt, iterations)
	if err != nil {
		t.Fatalf("CryptoPAKEValuesResponder failed: %v", err)
	}
	y, err := CryptoPAKERandomScalar()
	if err != nil {
		t.Fatalf("CryptoPAKERandomScalar failed: %v", err)
	}

	pB, err := CryptoPB(y, w0)
	if err != nil {
		t.Fatalf("CryptoPB failed: %v", err)
	}

	curve := elliptic.P256()
	yPx, yPy := curve.ScalarBaseMult(y)
	Nx, Ny := elliptic.Unmarshal(curve, spake2pN)
	if Nx == nil {
		t.Fatal("failed to unmarshal N")
	}
	w0Nx, w0Ny := curve.ScalarMult(Nx, Ny, w0)
	wantX, wantY := curve.Add(yPx, yPy, w0Nx, w0Ny)
	wantPB := elliptic.Marshal(curve, wantX, wantY)

	if !bytes.Equal(pB, wantPB) {
		t.Errorf("pB = %x, want %x (independently recomputed y*P + w0*N per 3.10.2)", pB, wantPB)
	}
}

// TestCryptoPAKESharedPointsResponderMatchesSpecIndependentRecomputation
// independently recomputes Z = y*(pA - w0*M) and V = y*L via raw
// crypto/elliptic calls, guarding against a regression in
// CryptoPAKESharedPointsResponder's formula (e.g. using the wrong generator
// point, or computing V from w1 instead of L).
func TestCryptoPAKESharedPointsResponderMatchesSpecIndependentRecomputation(t *testing.T) {
	passcode := []byte("testpasscode")
	salt := []byte("testsalt")
	iterations := 1000

	w0, l, err := CryptoPAKEValuesResponder(passcode, salt, iterations)
	if err != nil {
		t.Fatalf("CryptoPAKEValuesResponder failed: %v", err)
	}
	y, err := CryptoPAKERandomScalar()
	if err != nil {
		t.Fatalf("CryptoPAKERandomScalar failed: %v", err)
	}
	initW0, _, err := CryptoPAKEValuesInitiator(passcode, salt, iterations)
	if err != nil {
		t.Fatalf("CryptoPAKEValuesInitiator failed: %v", err)
	}
	x, err := CryptoPAKERandomScalar()
	if err != nil {
		t.Fatalf("CryptoPAKERandomScalar failed: %v", err)
	}
	pA, err := CryptoPA(x, initW0)
	if err != nil {
		t.Fatalf("CryptoPA failed: %v", err)
	}

	Z, V, err := CryptoPAKESharedPointsResponder(y, w0, l, pA)
	if err != nil {
		t.Fatalf("CryptoPAKESharedPointsResponder failed: %v", err)
	}

	curve := elliptic.P256()
	pAx, pAy := elliptic.Unmarshal(curve, pA)
	if pAx == nil {
		t.Fatal("failed to unmarshal pA")
	}
	Lx, Ly := elliptic.Unmarshal(curve, l)
	if Lx == nil {
		t.Fatal("failed to unmarshal L")
	}
	Mx, My := elliptic.Unmarshal(curve, spake2pM)
	if Mx == nil {
		t.Fatal("failed to unmarshal M")
	}
	w0Mx, w0My := curve.ScalarMult(Mx, My, w0)
	p := curve.Params().P
	negW0My := new(big.Int).Sub(p, w0My)
	negW0My.Mod(negW0My, p)
	tmpX, tmpY := curve.Add(pAx, pAy, w0Mx, negW0My)
	wantZx, wantZy := curve.ScalarMult(tmpX, tmpY, y)
	wantVx, wantVy := curve.ScalarMult(Lx, Ly, y)
	wantZ := elliptic.Marshal(curve, wantZx, wantZy)
	wantV := elliptic.Marshal(curve, wantVx, wantVy)

	if !bytes.Equal(Z, wantZ) {
		t.Errorf("Z = %x, want %x (independently recomputed y*(pA-w0*M) per 3.10.3)", Z, wantZ)
	}
	if !bytes.Equal(V, wantV) {
		t.Errorf("V = %x, want %x (independently recomputed y*L per 3.10.3)", V, wantV)
	}
}

// TestCryptoPAKEInitiatorResponderRoundTripAgreesOnSharedSecrets runs a full
// two-sided SPAKE2+ exchange — initiator (CryptoPAKEValuesInitiator/CryptoPA/
// CryptoPAKESharedPoints) against responder (CryptoPAKEValuesResponder/
// CryptoPB/CryptoPAKESharedPointsResponder) — and asserts both sides
// independently derive identical Z, V, cA, cB and Ke from the same
// passcode/salt/iterations. This is the regression this whole file's
// CryptoPB/CryptoPAKESharedPointsResponder additions exist for: prior to
// them, nothing in this package could even attempt a real two-party
// exchange, so a self-consistent-but-wrong formula on either side (as
// CryptoPB itself was) had no way to be caught by a test that only ever
// looked at one side in isolation.
func TestCryptoPAKEInitiatorResponderRoundTripAgreesOnSharedSecrets(t *testing.T) {
	passcode := []byte("testpasscode")
	salt := []byte("testsalt")
	iterations := 1000

	initW0, initW1, err := CryptoPAKEValuesInitiator(passcode, salt, iterations)
	if err != nil {
		t.Fatalf("CryptoPAKEValuesInitiator failed: %v", err)
	}
	respW0, respL, err := CryptoPAKEValuesResponder(passcode, salt, iterations)
	if err != nil {
		t.Fatalf("CryptoPAKEValuesResponder failed: %v", err)
	}
	if !bytes.Equal(initW0, respW0) {
		t.Fatalf("initiator w0 = %x, responder w0 = %x, want equal (both derived from the same passcode)", initW0, respW0)
	}

	x, err := CryptoPAKERandomScalar()
	if err != nil {
		t.Fatalf("CryptoPAKERandomScalar (x) failed: %v", err)
	}
	y, err := CryptoPAKERandomScalar()
	if err != nil {
		t.Fatalf("CryptoPAKERandomScalar (y) failed: %v", err)
	}

	pA, err := CryptoPA(x, initW0)
	if err != nil {
		t.Fatalf("CryptoPA failed: %v", err)
	}
	pB, err := CryptoPB(y, respW0)
	if err != nil {
		t.Fatalf("CryptoPB failed: %v", err)
	}

	initZ, initV, err := CryptoPAKESharedPoints(x, initW0, initW1, pB)
	if err != nil {
		t.Fatalf("CryptoPAKESharedPoints (initiator) failed: %v", err)
	}
	respZ, respV, err := CryptoPAKESharedPointsResponder(y, respW0, respL, pA)
	if err != nil {
		t.Fatalf("CryptoPAKESharedPointsResponder failed: %v", err)
	}

	if !bytes.Equal(initZ, respZ) {
		t.Errorf("initiator Z = %x, responder Z = %x, want equal", initZ, respZ)
	}
	if !bytes.Equal(initV, respV) {
		t.Errorf("initiator V = %x, responder V = %x, want equal", initV, respV)
	}

	pbkdfReq := []byte("pbkdf-param-request")
	pbkdfResp := []byte("pbkdf-param-response")

	initTT, err := CryptoTranscript(pbkdfReq, pbkdfResp, pA, pB, initZ, initV, initW0)
	if err != nil {
		t.Fatalf("CryptoTranscript (initiator) failed: %v", err)
	}
	respTT, err := CryptoTranscript(pbkdfReq, pbkdfResp, pA, pB, respZ, respV, respW0)
	if err != nil {
		t.Fatalf("CryptoTranscript (responder) failed: %v", err)
	}
	if !bytes.Equal(initTT, respTT) {
		t.Fatalf("initiator and responder transcripts differ despite equal Z/V/w0")
	}

	initCA, initCB, initKe, err := CryptoP2(initTT, pA, pB)
	if err != nil {
		t.Fatalf("CryptoP2 (initiator) failed: %v", err)
	}
	respCA, respCB, respKe, err := CryptoP2(respTT, pA, pB)
	if err != nil {
		t.Fatalf("CryptoP2 (responder) failed: %v", err)
	}

	if !bytes.Equal(initCA, respCA) {
		t.Errorf("initiator cA = %x, responder cA = %x, want equal", initCA, respCA)
	}
	if !bytes.Equal(initCB, respCB) {
		t.Errorf("initiator cB = %x, responder cB = %x, want equal", initCB, respCB)
	}
	if !bytes.Equal(initKe, respKe) {
		t.Errorf("initiator Ke = %x, responder Ke = %x, want equal", initKe, respKe)
	}
}
