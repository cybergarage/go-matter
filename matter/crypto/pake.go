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
	"encoding/binary"
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
	// Validate inputs
	if len(w0) != CryptoGroupSizeBytes {
		return nil, newErrInvalidLen("w0", CryptoGroupSizeBytes, len(w0))
	}
	if len(w1) != CryptoGroupSizeBytes {
		return nil, newErrInvalidLen("w1", CryptoGroupSizeBytes, len(w1))
	}
	// In the Matter/CHIP spec, pA is derived from the PAKE values.
	// Since w1 is a scalar, convert it to a curve point: pA = w1 * P.
	return cryptoPAKEMultP(w1)
}

// CryptoPB returns the public key pB computed by the responder using w0 and L.
// 3.10.2. Computation of pB.
func CryptoPB(w0, l []byte) ([]byte, error) {
	// Crypto_pB(Crypto_PAKEValues_Responder) :=
	//	byte pB[CRYPTO_PUBLIC_KEY_SIZE_BYTES]
	// Validate w0 length
	if len(w0) != CryptoGroupSizeBytes {
		return nil, newErrInvalidLen("w0", CryptoGroupSizeBytes, len(w0))
	}
	// L is already a curve point (w1 * P from CryptoPAKEValuesResponder),
	// so validate it and return.
	return cryptoValidatePoint(l)
}

// CryptoTranscript computes the transcript TT used for PAKE confirmation-key derivation.
// 3.10.3. Computation of transcript TT.
//
// Z and V are the shared elliptic-curve points computed during ECDH key agreement.
// w0 is the PAKE password element derived by CryptoPAKEValuesInitiator/Responder.
func CryptoTranscript(pbkdfParamRequest, pbkdfParamResponse, pA, pB, Z, V, w0 []byte) ([]byte, error) {
	// byte ContextPrefixValue [26] = "CHIP PAKE V1 Commissioning"
	// The usage of CHIP here is intentional and due to implementation in the SDK
	// before the name change; should not be renamed to Matter.
	contextPrefix := []byte{
		0x43, 0x48, 0x49, 0x50, 0x20, 0x50, 0x41, 0x4b, 0x45, 0x20, 0x56, 0x31, 0x20, 0x43,
		0x6f, 0x6d, 0x6d, 0x69, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x69, 0x6e, 0x67,
	}

	// Context := Crypto_Hash(ContextPrefixValue || PBKDFParamRequest || PBKDFParamResponse)
	contextInput := make([]byte, 0, len(contextPrefix)+len(pbkdfParamRequest)+len(pbkdfParamResponse))
	contextInput = append(contextInput, contextPrefix...)
	contextInput = append(contextInput, pbkdfParamRequest...)
	contextInput = append(contextInput, pbkdfParamResponse...)
	context := CryptoHash(contextInput)

	// Fixed SPAKE2+ generator points M and N for P-256 (uncompressed SEC1, 65 bytes).
	// From connectedhomeip / RFC 9383 Table 4.
	spake2pM := []byte{
		0x04, 0x88, 0x6e, 0x2f, 0x97, 0xac, 0xe4, 0x6e, 0x55, 0xba, 0x9d,
		0xd7, 0x24, 0x25, 0x79, 0xf2, 0x99, 0x3b, 0x64, 0xe1, 0x6e, 0xf3,
		0xdc, 0xab, 0x95, 0xaf, 0xd4, 0x97, 0x33, 0x3d, 0x8f, 0xa1, 0x2f,
		0x5f, 0xf3, 0x55, 0x16, 0x3e, 0x43, 0xce, 0x22, 0x4e, 0x0b, 0x0e,
		0x65, 0xff, 0x02, 0xac, 0x8e, 0x5c, 0x7b, 0xe0, 0x94, 0x19, 0xc7,
		0x85, 0xe0, 0xca, 0x54, 0x7d, 0x55, 0xa1, 0x2e, 0x2d, 0x20,
	}
	spake2pN := []byte{
		0x04, 0xd8, 0xbb, 0xd6, 0xc6, 0x39, 0xc6, 0x29, 0x37, 0xb0, 0x4d,
		0x99, 0x7f, 0x38, 0xc3, 0x77, 0x07, 0x19, 0xc6, 0x29, 0xd7, 0x01,
		0x4d, 0x49, 0xa2, 0x4b, 0x4f, 0x98, 0xba, 0xa1, 0x29, 0x2b, 0x49,
		0x07, 0xd6, 0x0a, 0xa6, 0xbf, 0xad, 0xe4, 0x50, 0x08, 0xa6, 0x36,
		0x33, 0x7f, 0x51, 0x68, 0xc6, 0x4d, 0x9b, 0xd3, 0x60, 0x34, 0x80,
		0x8c, 0xd5, 0x64, 0x49, 0x0b, 0x1e, 0x65, 0x6e, 0xdb, 0xe7,
	}

	// TT :=
	//   lengthInBytes(Context) || Context ||
	//   0x0000000000000000 || 0x0000000000000000 ||   (idProver=0, idVerifier=0)
	//   lengthInBytes(M) || M ||
	//   lengthInBytes(N) || N ||
	//   lengthInBytes(pA) || pA ||
	//   lengthInBytes(pB) || pB ||
	//   lengthInBytes(Z) || Z ||
	//   lengthInBytes(V) || V ||
	//   lengthInBytes(w0) || w0
	//
	// lengthInBytes is encoded as little-endian uint64.
	var tt []byte
	tt = appendSized(tt, context)
	tt = append(tt, make([]byte, 16)...) // idProver=0 (8 bytes) || idVerifier=0 (8 bytes)
	tt = appendSized(tt, spake2pM)
	tt = appendSized(tt, spake2pN)
	tt = appendSized(tt, pA)
	tt = appendSized(tt, pB)
	tt = appendSized(tt, Z)
	tt = appendSized(tt, V)
	tt = appendSized(tt, w0)
	return tt, nil
}

// CryptoP2 derives cA, cB, and Ke from the transcript TT.
// 3.10.4. Computation of cA, cB and Ke.
func CryptoP2(tt, pA, pB []byte) ([]byte, []byte, []byte, error) {
	if len(tt) == 0 {
		return nil, nil, nil, newErrInvalid("transcript")
	}
	if _, err := cryptoValidatePoint(pA); err != nil {
		return nil, nil, nil, fmt.Errorf("invalid pA: %w", err)
	}
	if _, err := cryptoValidatePoint(pB); err != nil {
		return nil, nil, nil, fmt.Errorf("invalid pB: %w", err)
	}

	kaKe := CryptoHash(tt)
	if len(kaKe) != CryptoHashLenBytes {
		return nil, nil, nil, newErrInvalidLen("Ka||Ke", CryptoHashLenBytes, len(kaKe))
	}

	half := CryptoHashLenBytes / 2
	ka := kaKe[:half]
	ke := kaKe[half:]
	cA := CryptoHMAC(ka, pB)
	cB := CryptoHMAC(ka, pA)
	return cA, cB, ke, nil
}

// appendSized appends a little-endian uint64 length prefix followed by data to dst.
func appendSized(dst, data []byte) []byte {
	var lenBuf [8]byte
	binary.LittleEndian.PutUint64(lenBuf[:], uint64(len(data)))
	dst = append(dst, lenBuf[:]...)
	dst = append(dst, data...)
	return dst
}

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

// cryptoValidatePoint validates that the input is a valid SEC1-encoded P-256 point.
func cryptoValidatePoint(pointBytes []byte) ([]byte, error) {
	curve := ellipticCurve
	// Check length: 0x04 || X || Y
	if len(pointBytes) != CryptoPublicKeySizeBytes {
		return nil, newErrInvalidLen("public key point", CryptoPublicKeySizeBytes, len(pointBytes))
	}
	// Check SEC1 uncompressed format prefix
	if pointBytes[0] != 0x04 {
		return nil, fmt.Errorf("invalid point encoding: expected 0x04 prefix, got 0x%02x", pointBytes[0])
	}
	// Unmarshal validates curve membership
	x, y := elliptic.Unmarshal(curve, pointBytes)
	if x == nil || y == nil {
		return nil, errors.New("point is not on P-256 curve")
	}
	// Re-marshal to ensure canonical form
	out := elliptic.Marshal(curve, x, y)
	if len(out) != CryptoPublicKeySizeBytes {
		return nil, newErrInvalidLen("marshaled point", CryptoPublicKeySizeBytes, len(out))
	}
	return out, nil
}
