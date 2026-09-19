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

package mockdevice

import (
	"crypto/elliptic"
	"encoding/binary"
	"fmt"

	"github.com/cybergarage/go-matter/matter/crypto"
)

// The formulas in this file are independently reimplemented from
// connectedhomeip source and Matter Core Spec, NOT reused from
// matter/protocol/case (whose equivalents are unexported and thus
// unreachable from this package anyway) — deliberately, since this exact
// class of formula (destination ID, operational-IPK derivation, Sigma2/3
// KDF salts) is what a chain of real bugs against a live device lived in
// earlier in this project's history (raw vs. HKDF-derived IPK being the
// most severe: it was self-consistent within matter/protocol/case's own
// code, so no test built by reusing that code's own helpers could ever
// have caught it — only an independent implementation, cross-checked
// against a real device or a real initiator, could). A future regression in
// either implementation is caught here specifically because the two sides
// don't share the buggy code.

// caseCryptoSymmetricKeyLen is the AES-CCM/HKDF key length (128 bits),
// matching matter/protocol/case's own (unexported) constant of the same
// meaning.
const caseCryptoSymmetricKeyLen = 16

// computeCompressedFabricIDBytes derives the 8-byte compressed fabric
// identifier: HKDF-SHA256(IKM=rootPublicKey[1:] (drops the 0x04 SEC1
// uncompressed-point prefix), salt=fabricID (8 bytes, big-endian),
// info="CompressedFabric", L=8). Matter Core Spec Appendix, "Compressed
// Fabric Identifier" / connectedhomeip's FabricTable::ComputeCompressedFabricId.
func computeCompressedFabricIDBytes(rootPublicKey []byte, fabricID uint64) ([]byte, error) {
	if len(rootPublicKey) < 2 {
		return nil, fmt.Errorf("mockdevice: invalid root public key")
	}
	fabricIDBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(fabricIDBytes, fabricID)
	return crypto.CryptoKDF(rootPublicKey[1:], fabricIDBytes, []byte("CompressedFabric"), 8)
}

// deriveOperationalIPK derives the fabric's operational Identity Protection
// Key from the raw 16-byte epoch key AddNOC's IPKValue field carried:
// HKDF-SHA256(IKM=rawIPK, salt=compressedFabricID (8 bytes), info="GroupKey v1.0",
// L=16). connectedhomeip's GroupDataProviderImpl::SetKeySet
// (src/credentials/GroupDataProviderImpl.cpp) performs exactly this
// derivation when AddNOC's own handler stores the fabric's IPK — a real
// device never uses the raw epoch key directly for anything past that
// point, including CASE's DestinationID.
func deriveOperationalIPK(rawIPK, compressedFabricIDBytes []byte) ([]byte, error) {
	return crypto.CryptoKDF(rawIPK, compressedFabricIDBytes, []byte("GroupKey v1.0"), caseCryptoSymmetricKeyLen)
}

// computeDestinationID computes Sigma1's DestinationID candidate:
// HMAC-SHA256(operationalIPK, initiatorRandom || rootPublicKey ||
// fabricID(8, little-endian) || nodeID(8, little-endian)) — connectedhomeip's
// GenerateCaseDestinationId (src/protocols/secure_channel/CASEDestinationId.cpp).
func computeDestinationID(operationalIPK, initiatorRandom, rootPublicKey []byte, fabricID, nodeID uint64) []byte {
	fabricIDBytes := make([]byte, 8)
	nodeIDBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(fabricIDBytes, fabricID)
	binary.LittleEndian.PutUint64(nodeIDBytes, nodeID)
	msg := make([]byte, 0, len(initiatorRandom)+len(rootPublicKey)+16)
	msg = append(msg, initiatorRandom...)
	msg = append(msg, rootPublicKey...)
	msg = append(msg, fabricIDBytes...)
	msg = append(msg, nodeIDBytes...)
	return crypto.CryptoHMAC(operationalIPK, msg)
}

// ecdhSharedSecretX returns just the X coordinate of the ECDH shared point
// priv * peerPub, fixed-width 32 bytes — the shared secret CASE's Sigma2/3
// key derivations use, per connectedhomeip's use of the raw ECDH X
// coordinate (not a KDF-processed value) as their shared-secret input.
func ecdhSharedSecretX(priv []byte, peerPubBytes []byte) ([]byte, error) {
	curve := elliptic.P256()
	x, y := elliptic.Unmarshal(curve, peerPubBytes)
	if x == nil || y == nil {
		return nil, fmt.Errorf("mockdevice: invalid peer ephemeral public key")
	}
	sharedX, _ := curve.ScalarMult(x, y, priv)
	if sharedX == nil {
		return nil, fmt.Errorf("mockdevice: ECDH failed")
	}
	return sharedX.FillBytes(make([]byte, 32)), nil
}

// deriveSigma2Key derives S2K: HKDF-SHA256(IKM=sharedSecret,
// salt=operationalIPK||responderRandom||responderEphPubKey||SHA256(sigma1RawPayload),
// info="Sigma2", L=16).
func deriveSigma2Key(sharedSecret, operationalIPK, responderRandom, responderEphPubKey, sigma1Payload []byte) ([]byte, error) {
	transcriptHash := crypto.CryptoHash(sigma1Payload)
	salt := append(append([]byte(nil), operationalIPK...), responderRandom...)
	salt = append(salt, responderEphPubKey...)
	salt = append(salt, transcriptHash...)
	return crypto.CryptoKDF(sharedSecret, salt, []byte("Sigma2"), caseCryptoSymmetricKeyLen)
}

// deriveSigma3Key derives S3K: HKDF-SHA256(IKM=sharedSecret,
// salt=operationalIPK||SHA256(sigma1Payload||sigma2Payload), info="Sigma3", L=16).
func deriveSigma3Key(sharedSecret, operationalIPK, sigma1Payload, sigma2Payload []byte) ([]byte, error) {
	transcript := append(append([]byte(nil), sigma1Payload...), sigma2Payload...)
	transcriptHash := crypto.CryptoHash(transcript)
	salt := append(append([]byte(nil), operationalIPK...), transcriptHash...)
	return crypto.CryptoKDF(sharedSecret, salt, []byte("Sigma3"), caseCryptoSymmetricKeyLen)
}

// deriveCASESessionKeys derives the final I2R/R2I session keys:
// HKDF-SHA256(IKM=sharedSecret, salt=operationalIPK||SHA256(sigma1Payload||sigma2Payload||sigma3Payload),
// info="SessionKeys", L=48) — the third 16-byte segment (unlike PASE's,
// which yields an AttestationChallenge) is unused, matching
// session.SessionKeys' own doc comment that CASE sessions have no
// AttestationChallenge.
func deriveCASESessionKeys(sharedSecret, operationalIPK, sigma1Payload, sigma2Payload, sigma3Payload []byte) ([]byte, []byte, error) {
	transcript := append(append([]byte(nil), sigma1Payload...), sigma2Payload...)
	transcript = append(transcript, sigma3Payload...)
	transcriptHash := crypto.CryptoHash(transcript)
	salt := append(append([]byte(nil), operationalIPK...), transcriptHash...)
	derived, err := crypto.CryptoKDF(sharedSecret, salt, []byte("SessionKeys"), 3*caseCryptoSymmetricKeyLen)
	if err != nil {
		return nil, nil, err
	}
	return derived[0:caseCryptoSymmetricKeyLen], derived[caseCryptoSymmetricKeyLen : 2*caseCryptoSymmetricKeyLen], nil
}
