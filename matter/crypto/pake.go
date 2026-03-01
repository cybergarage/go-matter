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
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"
)

// 3.10. Password-Authenticated Key Exchange (PAKE).
const (
	// CryptoWSizeBytes := CRYPTO_GROUP_SIZE_BYTES + 8.
	CryptoWSizeBytes = CryptoGroupSizeBytes + 8
	// CryptoWSizeBits := CRYPTO_W_SIZE_BYTES * 8.
	CryptoWSizeBits = CryptoWSizeBytes * 8
)

// CryptoPAKEValuesInitiator := (w0, w1) where w0 and w1 SHALL be computed as follows:
// 3.10. Password-Authenticated Key Exchange (PAKE).
func CryptoPAKEValuesInitiator(passcode []byte, salt []byte, iterations int) ([]byte, []byte, error) {
	// Crypto_PAKEValues_Initiator := (w0, w1) where w0 and w1 SHALL be computed as follows:
	// byte w0s[CRYPTO_W_SIZE_BYTES] || byte w1s[CRYPTO_W_SIZE_BYTES] =
	//
	//	(byte[2 * CRYPTO_W_SIZE_BYTES])
	//	bit[2 * CRYPTO_W_SIZE_BITS]
	//	Crypto_PBKDF(passcode, salt, iterations, 2 * CRYPTO_W_SIZE_BITS)
	//
	// byte w0[CRYPTO_GROUP_SIZE_BYTES] = w0s mod p
	// byte w1[CRYPTO_GROUP_SIZE_BYTES] = w1s mod p.
	ws, err := CryptoPBKDF(passcode, salt, iterations, CryptoWSizeBytes)
	if err != nil {
		return nil, nil, err
	}
	if len(ws) != CryptoWSizeBytes {
		return nil, nil, newErrInvalidLen("CryptoPBKDF output", CryptoWSizeBytes, len(ws))
	}

	w0s := ws[:CryptoGroupSizeBytes]
	w1s := ws[CryptoGroupSizeBytes:]

	w0 := cryptoPAKEModP(w0s)
	w1 := cryptoPAKEModP(w1s)

	return w0, w1, nil
}

// CryptoPAKEValuesResponder := (w0, L) where w0 and L SHALL be computed as follows:
// 3.10. Password-Authenticated Key Exchange (PAKE).
func CryptoPAKEValuesResponder(passcode []byte, salt []byte, iterations int) ([]byte, []byte, error) {
	// Crypto_PAKEValues_Responder := (w0, L) where w0 and L SHALL be computed as follows:
	// byte w0s[CRYPTO_W_SIZE_BYTES] || byte w1s[CRYPTO_W_SIZE_BYTES] =
	//
	//	(byte[2 * CRYPTO_W_SIZE_BYTES])
	//	bit[2 * CRYPTO_W_SIZE_BITS]
	//	Crypto_PBKDF(passcode, salt, iterations, 2 * CRYPTO_W_SIZE_BITS)
	//
	// byte w0[CRYPTO_GROUP_SIZE_BYTES] = w0s mod p
	// byte w1[CRYPTO_GROUP_SIZE_BYTES] = w1s mod p
	// byte L[CRYPTO_PUBLIC_KEY_SIZE_BYTES] = w1 * P.
	ws, err := CryptoPBKDF(passcode, salt, iterations, CryptoWSizeBytes)
	if err != nil {
		return nil, nil, err
	}
	if len(ws) != CryptoWSizeBytes {
		return nil, nil, newErrInvalidLen("CryptoPBKDF output", CryptoWSizeBytes, len(ws))
	}

	w0s := ws[:CryptoGroupSizeBytes]
	w1s := ws[CryptoGroupSizeBytes:]
	w0 := cryptoPAKEModP(w0s)
	w1 := cryptoPAKEModP(w1s)

	l, err := cryptoPAKEMultP(w1)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive responder public key: %w", err)
	}

	return w0, l, nil
}

// CryptoPA returns the public key pA computed by the initiator using w0 and w1.
// 3.10.1. Computation of pA.
func CryptoPA(w0, w1 []byte) ([]byte, error) {
	// Crypto_pA(Crypto_PAKEValues_Initiator) :=
	//   byte pA[CRYPTO_PUBLIC_KEY_SIZE_BYTES]
	return cryptoP(w0, w1)
}

// CryptoPB returns the public key pB computed by the responder using w0 and L.
// 3.10.2. Computation of pB.
func CryptoPB(w0, l []byte) ([]byte, error) {
	// Crypto_pB(Crypto_PAKEValues_Responder) :=
	//	byte pB[CRYPTO_PUBLIC_KEY_SIZE_BYTES]
	return cryptoP(w0, l)
}

// 3.10.3. Computation of transcript TT
// Crypto_Transcript(PBKDFParamRequest, PBKDFParamResponse, pA, pB) :=
//   byte[] TT
// byte ContextPrefixValue [26] = {
// 0x43, 0x48, 0x49, 0x50, 0x20, 0x50, 0x41, 0x4b, 0x45, 0x20, 0x56, 0x31, 0x20, 0x43,
// 0x6f, 0x6d,
// 0x6d, 0x69, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x69, 0x6e, 0x67
// } // "CHIP PAKE V1 Commissioning" - The usage of CHIP here is intentional and due to
// implementation in the SDK before the name change, should not be renamed to Matter.
// Context := Crypto_Hash(ContextPrefixValue || PBKDFParamRequest || PBKDFParamResponse)
// TT :=
//   lengthInBytes(Context) || Context ||
//   0x0000000000000000 || 0x0000000000000000 ||
//   lengthInBytes(M) || M ||
//   lengthInBytes(N) || N ||
//   lengthInBytes(pA) || pA ||
//   lengthInBytes(pB) || pB ||
//   lengthInBytes(Z) || Z ||
//   lengthInBytes(V) || V ||
//   lengthInBytes(w0) || w0

// 3.10.4. Computation of cA, cB and Ke
// Crypto_P2(TT, pA, pB) :=
//   {byte cA[CRYPTO_HASH_LEN_BYTES],
//   byte cB[CRYPTO_HASH_LEN_BYTES],
//   byte Ke[CRYPTO_HASH_LEN_BYTES/2]}

func cryptoPAKEModP(in []byte) []byte {
	p := ellipticCurve.Params().P
	n := new(big.Int).SetBytes(in)
	n.Mod(n, p)
	out := n.Bytes()
	if len(out) >= CryptoGroupSizeBytes {
		return out[len(out)-CryptoGroupSizeBytes:]
	}
	fixed := make([]byte, CryptoGroupSizeBytes)
	copy(fixed[CryptoGroupSizeBytes-len(out):], out)
	return fixed
}

func cryptoPAKEMultP(in []byte) ([]byte, error) {
	curve := ellipticCurve
	x, y := curve.ScalarBaseMult(in)
	if x == nil || y == nil {
		return nil, fmt.Errorf("failed to derive public key")
	}
	out := elliptic.Marshal(curve, x, y)
	if len(out) != CryptoPublicKeySizeBytes {
		return nil, newErrInvalidLen("public key", CryptoPublicKeySizeBytes, len(out))
	}
	return out, nil
}

func cryptoP(xb, yb []byte) ([]byte, error) {
	curve := ellipticCurve
	p := curve.Params().P
	// Basic length sanity (avoid absurd sizes)
	if len(xb) != CryptoGroupSizeBytes || len(yb) != CryptoGroupSizeBytes {
		return nil, fmt.Errorf("invalid coordinate length: expected %d bytes each, got %d and %d", CryptoGroupSizeBytes, len(xb), len(yb))
	}
	// Convert to big.Int (treat as unsigned big-endian)
	x := new(big.Int).SetBytes(xb)
	y := new(big.Int).SetBytes(yb)
	// Range checks: 0 <= x,y < p
	// (elliptic.Marshal doesn't validate curve membership; Unmarshal does on decode,
	//  but for safety we validate here too.)
	if x.Sign() < 0 || y.Sign() < 0 {
		return nil, errors.New("negative coordinate")
	}
	if x.Cmp(p) >= 0 || y.Cmp(p) >= 0 {
		return nil, errors.New("coordinate out of field range")
	}
	// Curve membership check
	if !curve.IsOnCurve(x, y) {
		return nil, errors.New("point is not on P-256 curve")
	}
	// SEC1 uncompressed encoding: 0x04||X||Y (fixed width)
	pA := elliptic.Marshal(curve, x, y)
	if len(pA) != CryptoPublicKeySizeBytes || pA[0] != 0x04 {
		return nil, fmt.Errorf("unexpected encoding: len=%d prefix=0x%02x", len(pA), pA[0])
	}
	return pA, nil
}
