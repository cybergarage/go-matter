// Copyright (C) 2026 The go-matter Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package credentials

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	mcrypto "github.com/cybergarage/go-matter/matter/crypto"
)

// Signer signs with a P-256 key (Matter Core 3.5.3). The private key does
// not have to leave the signer, so a Signer can be backed by a secure
// element, a TPM or an HSM; NewSoftwareSigner holds the key in memory.
type Signer interface {
	// PublicKey returns the public key of the signing key.
	PublicKey() *ecdsa.PublicKey
	// Sign returns the ECDSA signature over the SHA-256 hash of msg, as
	// the 64-byte r||s encoding Matter carries on the wire (Crypto_Sign).
	Sign(msg []byte) ([]byte, error)
}

type softwareSigner struct {
	priv *ecdsa.PrivateKey
}

// NewSoftwareSigner returns a Signer which holds priv in memory.
func NewSoftwareSigner(priv *ecdsa.PrivateKey) (Signer, error) {
	if priv == nil || priv.Curve != elliptic.P256() {
		return nil, errors.New("credentials: a P-256 private key is required")
	}
	return &softwareSigner{priv: priv}, nil
}

// GenerateSoftwareSigner returns a Signer with a new random P-256 key, such
// as the operational key a device generates for a CSRRequest.
func GenerateSoftwareSigner() (Signer, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("credentials: generate a key: %w", err)
	}
	return NewSoftwareSigner(priv)
}

// ParseSoftwareSigner returns a Signer for a DER-encoded P-256 private key,
// in SEC 1 or PKCS #8 form.
func ParseSoftwareSigner(der []byte) (Signer, error) {
	if priv, err := x509.ParseECPrivateKey(der); err == nil {
		return NewSoftwareSigner(priv)
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("credentials: parse a private key: %w", err)
	}
	priv, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("credentials: the private key is not an ECDSA key")
	}
	return NewSoftwareSigner(priv)
}

func (s *softwareSigner) PublicKey() *ecdsa.PublicKey {
	return &s.priv.PublicKey
}

func (s *softwareSigner) Sign(msg []byte) ([]byte, error) {
	sig, err := mcrypto.CryptoSign(mcrypto.NewPrivateKey(s.priv), msg)
	if err != nil {
		return nil, fmt.Errorf("credentials: sign: %w", err)
	}
	out := make([]byte, rawSignatureLen)
	r, rs := sig.R(), sig.S()
	copy(out[32-len(r):32], r)
	copy(out[64-len(rs):64], rs)
	return out, nil
}

// VerifySignature reports whether sig, a 64-byte r||s signature, is pub's
// signature over msg.
func VerifySignature(pub *ecdsa.PublicKey, msg, sig []byte) error {
	return verifyRawSignature(pub, msg, sig)
}

// Object identifier of ecdsa-with-SHA256 (RFC 5758, 3.2).
var oidSignatureECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}

// certificationRequestInfo and certificationRequest are the PKCS #10
// structures (RFC 2986, 4).
type certificationRequestInfo struct {
	Version       int
	Subject       asn1.RawValue
	PublicKeyInfo asn1.RawValue
	Attributes    asn1.RawValue `asn1:"tag:0"`
}

type certificationRequest struct {
	Info               asn1.RawValue
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
}

// CreateCSR returns a PKCS #10 certificate signing request, DER-encoded,
// for signer's key, as a device answers a CSRRequest with (Matter Core
// 6.4.6.1, 11.18.6.5). The subject is "O=CSR", the placeholder the
// reference implementation uses: the commissioner decides the NOC's subject.
//
// The request is encoded here rather than with x509.CreateCertificateRequest,
// which only hands a signer the digest to sign, while a Signer signs the
// message itself.
func CreateCSR(signer Signer) ([]byte, error) {
	subject, err := asn1.Marshal(pkix.Name{Organization: []string{"CSR"}}.ToRDNSequence()) // nolint: exhaustruct
	if err != nil {
		return nil, fmt.Errorf("credentials: CSR subject: %w", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(signer.PublicKey())
	if err != nil {
		return nil, fmt.Errorf("credentials: CSR public key: %w", err)
	}
	info, err := asn1.Marshal(certificationRequestInfo{
		Version:       0,
		Subject:       asn1.RawValue{FullBytes: subject},
		PublicKeyInfo: asn1.RawValue{FullBytes: spki},
		// No attributes: an empty [0] IMPLICIT SET OF Attribute.
		Attributes: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: []byte{}},
	})
	if err != nil {
		return nil, fmt.Errorf("credentials: CSR info: %w", err)
	}
	raw, err := signer.Sign(info)
	if err != nil {
		return nil, err
	}
	sig, err := asn1.Marshal(struct{ R, S *big.Int }{
		R: new(big.Int).SetBytes(raw[:32]),
		S: new(big.Int).SetBytes(raw[32:]),
	})
	if err != nil {
		return nil, fmt.Errorf("credentials: CSR signature: %w", err)
	}
	csr, err := asn1.Marshal(certificationRequest{
		Info:               asn1.RawValue{FullBytes: info},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidSignatureECDSAWithSHA256}, // nolint: exhaustruct
		Signature:          asn1.BitString{Bytes: sig, BitLength: 8 * len(sig)},
	})
	if err != nil {
		return nil, fmt.Errorf("credentials: CSR: %w", err)
	}
	return csr, nil
}
