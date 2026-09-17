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

package credentials

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"

	mcrypto "github.com/cybergarage/go-matter/matter/crypto"
)

// rawSignatureLen is the length of a raw (r||s) P-256 ECDSA signature, per
// 3.5.3. Signature and verification.
const rawSignatureLen = 64

type rawSignature struct {
	r []byte
	s []byte
}

func (s rawSignature) R() []byte { return s.r }
func (s rawSignature) S() []byte { return s.s }

func parseRawSignature(b []byte) (mcrypto.Signature, error) {
	if len(b) != rawSignatureLen {
		return nil, fmt.Errorf("invalid signature length %d, want %d", len(b), rawSignatureLen)
	}
	return rawSignature{
		r: new(big.Int).SetBytes(b[:32]).Bytes(),
		s: new(big.Int).SetBytes(b[32:]).Bytes(),
	}, nil
}

// verifyRawSignature verifies sigBytes (raw r||s per 3.5.3) over msg using
// the given DAC public key, via matter/crypto's Crypto_Verify primitive.
func verifyRawSignature(pub *ecdsa.PublicKey, msg, sigBytes []byte) error {
	sig, err := parseRawSignature(sigBytes)
	if err != nil {
		return fmt.Errorf("parse signature: %w", err)
	}
	if !mcrypto.CryptoVerify(mcrypto.NewPublicKey(pub), msg, sig) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}
