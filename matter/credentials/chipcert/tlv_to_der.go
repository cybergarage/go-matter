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

package chipcert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	"github.com/cybergarage/go-matter/matter/encoding/tlv"
)

// Real X.509 extension OIDs (RFC 5280 / gen_asn1oid.py "Extension" category).
var (
	oidExtBasicConstraints     = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidExtKeyUsage             = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtExtendedKeyUsage     = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidExtSubjectKeyIdentifier = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidExtAuthorityKeyID       = asn1.ObjectIdentifier{2, 5, 29, 35}
)

// certificate/tbsCertificate/validity mirror the RFC 5280 X.509 Certificate
// ASN.1 structure (the same shape crypto/x509 uses internally, redefined here
// because those types are unexported by the standard library).
type certificate struct {
	TBSCertificate     tbsCertificate
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

type tbsCertificate struct {
	Version            int `asn1:"explicit,tag:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Issuer             asn1.RawValue
	Validity           validity
	Subject            asn1.RawValue
	PublicKey          asn1.RawValue
	Extensions         []pkix.Extension `asn1:"omitempty,optional,explicit,tag:3"`
}

type validity struct {
	NotBefore, NotAfter time.Time
}

// basicConstraints mirrors RFC 5280's BasicConstraints extension value.
type basicConstraints struct {
	IsCA       bool `asn1:"optional"`
	MaxPathLen int  `asn1:"optional,default:-1"`
}

// authKeyID mirrors RFC 5280's AuthorityKeyIdentifier extension value,
// restricted to the keyIdentifier field (the only one this codec produces).
type authKeyID struct {
	ID []byte `asn1:"optional,tag:0"`
}

// TLVToDER converts a Matter-TLV CHIPCert (as returned by a device's
// CertificateChainRequest, or embedded in a CASE Sigma2/Sigma3 message) into
// a DER-encoded X.509 certificate.
//
// The reconstructed DER is only guaranteed to reproduce, byte for byte, the
// original DER that a well-behaved implementation of the compact TLV
// encoding (this package, or the connectedhomeip reference) would have
// started from — which is what a signature originally computed over that
// certificate was signed against. Certificate fields or extensions this
// package does not recognize are dropped rather than rejected (see
// encodeRDN); that is safe for verifying a certificate's own signature and
// public key (this codebase's use of DAC/PAI certificates is limited to
// exactly that, see matter/credentials/attestation.go), but the
// reconstructed DER is not guaranteed to be identical to arbitrary
// third-party output beyond the fields this package understands.
func TLVToDER(tlvBytes []byte) ([]byte, error) {
	dec := tlv.NewDecoderWithBytes(tlvBytes)
	if !dec.Next() {
		if err := dec.Error(); err != nil {
			return nil, fmt.Errorf("chipcert: %w", err)
		}
		return nil, fmt.Errorf("chipcert: empty TLV certificate")
	}
	if !dec.Element().Type().IsStructure() {
		return nil, fmt.Errorf("chipcert: expected top-level Structure")
	}

	var (
		serial              *big.Int
		issuerATVs          []pkix.AttributeTypeAndValue
		subjectATVs         []pkix.AttributeTypeAndValue
		notBefore, notAfter time.Time
		pubKeyBytes, rawSig []byte
		extensions          []pkix.Extension
		haveIssuer, haveNB  bool
		haveNA, haveSubject bool
		havePubKey, haveSig bool
	)

	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			break
		}
		ct, ok := elem.Tag().(tlv.ContextTag)
		if !ok {
			return nil, fmt.Errorf("chipcert: certificate field has non-context tag")
		}
		switch ct.ContextNumber() {
		case tagSerialNumber:
			b, ok := elem.Bytes()
			if !ok {
				return nil, fmt.Errorf("chipcert: SerialNumber is not an octet string")
			}
			serial = new(big.Int).SetBytes(b)
		case tagSignatureAlgorithm, tagPublicKeyAlgorithm, tagEllipticCurveIdentifier:
			if _, ok := elem.Unsigned(); !ok {
				return nil, fmt.Errorf("chipcert: algorithm field is not an integer")
			}
		case tagIssuer:
			atvs, err := decodeDNFields(dec)
			if err != nil {
				return nil, fmt.Errorf("chipcert: decode Issuer: %w", err)
			}
			issuerATVs = atvs
			haveIssuer = true
		case tagNotBefore:
			v, ok := elem.Unsigned4()
			if !ok {
				return nil, fmt.Errorf("chipcert: NotBefore is not an integer")
			}
			notBefore = chipEpochToTime(v)
			haveNB = true
		case tagNotAfter:
			v, ok := elem.Unsigned4()
			if !ok {
				return nil, fmt.Errorf("chipcert: NotAfter is not an integer")
			}
			notAfter = chipEpochToTime(v)
			haveNA = true
		case tagSubject:
			atvs, err := decodeDNFields(dec)
			if err != nil {
				return nil, fmt.Errorf("chipcert: decode Subject: %w", err)
			}
			subjectATVs = atvs
			haveSubject = true
		case tagEllipticCurvePublicKey:
			b, ok := elem.Bytes()
			if !ok {
				return nil, fmt.Errorf("chipcert: EllipticCurvePublicKey is not an octet string")
			}
			pubKeyBytes = b
			havePubKey = true
		case tagExtensions:
			ext, err := decodeExtensionFields(dec)
			if err != nil {
				return nil, fmt.Errorf("chipcert: decode Extensions: %w", err)
			}
			extensions = ext
		case tagECDSASignature:
			b, ok := elem.Bytes()
			if !ok {
				return nil, fmt.Errorf("chipcert: ECDSASignature is not an octet string")
			}
			rawSig = b
			haveSig = true
		}
	}
	if err := dec.Error(); err != nil {
		return nil, fmt.Errorf("chipcert: %w", err)
	}
	if serial == nil || !haveIssuer || !haveSubject || !haveNB || !haveNA || !havePubKey || !haveSig {
		return nil, fmt.Errorf("chipcert: certificate missing required field(s)")
	}

	x, y := elliptic.Unmarshal(elliptic.P256(), pubKeyBytes)
	if x == nil {
		return nil, fmt.Errorf("chipcert: invalid EllipticCurvePublicKey")
	}
	spkiDER, err := x509.MarshalPKIXPublicKey(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y})
	if err != nil {
		return nil, fmt.Errorf("chipcert: marshal public key: %w", err)
	}

	issuerDER, err := marshalRDNSequence(issuerATVs)
	if err != nil {
		return nil, fmt.Errorf("chipcert: marshal Issuer: %w", err)
	}
	subjectDER, err := marshalRDNSequence(subjectATVs)
	if err != nil {
		return nil, fmt.Errorf("chipcert: marshal Subject: %w", err)
	}

	sigAlgID := pkix.AlgorithmIdentifier{Algorithm: oidSigECDSAWithSHA256}
	sigDER, err := rawSignatureToDER(rawSig)
	if err != nil {
		return nil, fmt.Errorf("chipcert: convert signature: %w", err)
	}

	cert := certificate{
		TBSCertificate: tbsCertificate{
			Version:            2, // v3: required whenever extensions are present.
			SerialNumber:       serial,
			SignatureAlgorithm: sigAlgID,
			Issuer:             asn1.RawValue{FullBytes: issuerDER},
			Validity:           validity{NotBefore: notBefore, NotAfter: notAfter},
			Subject:            asn1.RawValue{FullBytes: subjectDER},
			PublicKey:          asn1.RawValue{FullBytes: spkiDER},
			Extensions:         extensions,
		},
		SignatureAlgorithm: sigAlgID,
		SignatureValue:     asn1.BitString{Bytes: sigDER, BitLength: len(sigDER) * 8},
	}

	der, err := asn1.Marshal(cert)
	if err != nil {
		return nil, fmt.Errorf("chipcert: marshal certificate: %w", err)
	}
	return der, nil
}

// decodeDNFields decodes the RDN elements of an Issuer/Subject List, assuming
// the caller has already consumed the List-begin marker. It stops at (and
// consumes) the matching EndOfContainer marker.
func decodeDNFields(dec tlv.Decoder) ([]pkix.AttributeTypeAndValue, error) {
	var atvs []pkix.AttributeTypeAndValue
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			return atvs, dec.Error()
		}
		ct, ok := elem.Tag().(tlv.ContextTag)
		if !ok {
			return nil, fmt.Errorf("DN element has non-context tag")
		}
		attrEnum := int(ct.ContextNumber()) & attrTypeMask
		switch attrEnum {
		case oidEnumCommonName:
			s, ok := elem.UTF8()
			if !ok {
				return nil, fmt.Errorf("CommonName DN element is not a string")
			}
			atvs = append(atvs, utf8Attr(oidCommonName, s))
		default:
			if oid, ok := matterOIDForEnum(attrEnum); ok {
				v, ok := elem.Unsigned()
				if !ok {
					return nil, fmt.Errorf("matter DN element is not an integer")
				}
				atvs = append(atvs, utf8Attr(oid, uint64ToHexRDN(v)))
			}
			// Unknown DN attribute type: already consumed by dec.Next(); dropped
			// from the reconstructed DN (see encodeRDN's matching comment).
		}
	}
	return nil, dec.Error()
}

// decodeExtensionFields decodes the Extensions List, assuming the caller has
// already consumed the List-begin marker. BasicConstraints, KeyUsage and
// ExtendedKeyUsage are all reconstructed with Critical: true, matching
// connectedhomeip's device-side TLV-to-X509 reconstruction
// (src/credentials/CHIPCertToX509.cpp DecodeConvertExtension), which treats
// all three as critical unconditionally when rebuilding the TBS bytes it
// hashes for signature verification, regardless of what the original signed
// DER (if any) actually had.
func decodeExtensionFields(dec tlv.Decoder) ([]pkix.Extension, error) {
	var out []pkix.Extension
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			return out, dec.Error()
		}
		ct, ok := elem.Tag().(tlv.ContextTag)
		if !ok {
			return nil, fmt.Errorf("extension element has non-context tag")
		}
		switch ct.ContextNumber() {
		case tagExtBasicConstraints:
			if !elem.Type().IsStructure() {
				return nil, fmt.Errorf("BasicConstraints is not a structure")
			}
			bc, err := decodeBasicConstraints(dec)
			if err != nil {
				return nil, err
			}
			val, err := asn1.Marshal(bc)
			if err != nil {
				return nil, err
			}
			out = append(out, pkix.Extension{Id: oidExtBasicConstraints, Critical: true, Value: val})
		case tagExtKeyUsage:
			v, ok := elem.Unsigned2()
			if !ok {
				return nil, fmt.Errorf("KeyUsage is not an integer")
			}
			val, err := marshalKeyUsage(v)
			if err != nil {
				return nil, err
			}
			out = append(out, pkix.Extension{Id: oidExtKeyUsage, Critical: true, Value: val})
		case tagExtExtendedKeyUsage:
			if !elem.Type().IsArray() {
				return nil, fmt.Errorf("ExtendedKeyUsage is not an array")
			}
			oids, err := decodeExtKeyUsageArray(dec)
			if err != nil {
				return nil, err
			}
			val, err := asn1.Marshal(oids)
			if err != nil {
				return nil, err
			}
			out = append(out, pkix.Extension{Id: oidExtExtendedKeyUsage, Critical: true, Value: val})
		case tagExtSubjectKeyIdentifier:
			b, ok := elem.Bytes()
			if !ok {
				return nil, fmt.Errorf("SubjectKeyIdentifier is not an octet string")
			}
			val, err := asn1.Marshal(b)
			if err != nil {
				return nil, err
			}
			out = append(out, pkix.Extension{Id: oidExtSubjectKeyIdentifier, Value: val})
		case tagExtAuthorityKeyIdentifier:
			b, ok := elem.Bytes()
			if !ok {
				return nil, fmt.Errorf("AuthorityKeyIdentifier is not an octet string")
			}
			val, err := asn1.Marshal(authKeyID{ID: b})
			if err != nil {
				return nil, err
			}
			out = append(out, pkix.Extension{Id: oidExtAuthorityKeyID, Value: val})
		}
	}
	return nil, dec.Error()
}

func decodeBasicConstraints(dec tlv.Decoder) (basicConstraints, error) {
	bc := basicConstraints{MaxPathLen: -1}
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			return bc, dec.Error()
		}
		ct, ok := elem.Tag().(tlv.ContextTag)
		if !ok {
			return basicConstraints{}, fmt.Errorf("BasicConstraints field has non-context tag")
		}
		switch ct.ContextNumber() {
		case tagBasicConstraintsIsCA:
			v, ok := elem.Bool()
			if !ok {
				return basicConstraints{}, fmt.Errorf("IsCA is not a boolean")
			}
			bc.IsCA = v
		case tagBasicConstraintsPathLenConstraint:
			v, ok := elem.Unsigned1()
			if !ok {
				return basicConstraints{}, fmt.Errorf("PathLenConstraint is not an integer")
			}
			bc.MaxPathLen = int(v)
		}
	}
	return basicConstraints{}, dec.Error()
}

func decodeExtKeyUsageArray(dec tlv.Decoder) ([]asn1.ObjectIdentifier, error) {
	var oids []asn1.ObjectIdentifier
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			return oids, dec.Error()
		}
		v, ok := elem.Unsigned1()
		if !ok {
			return nil, fmt.Errorf("ExtendedKeyUsage element is not an integer")
		}
		switch v {
		case keyPurposeServerAuth:
			oids = append(oids, oidExtKeyUsageServerAuth)
		case keyPurposeClientAuth:
			oids = append(oids, oidExtKeyUsageClientAuth)
		}
	}
	return nil, dec.Error()
}

// utf8Attr builds a DN attribute whose value is explicitly tagged as an
// ASN.1 UTF8String, rather than left to encoding/asn1's default heuristic
// (which picks PrintableString for content — like our all-digit Matter ID
// hex strings, or a plain CommonName — that fits PrintableString's narrower
// character set). connectedhomeip's own certificate reconstruction
// (src/credentials/CHIPCert.cpp ChipDN::EncodeToASN1) always emits
// UTF8String for these fields, and matter/credentials/ca.go and
// mattertest/certs/certgen.go now sign certificates with UTF8String too
// (see their matching utf8Attr helpers) — this reconstruction must match,
// or the DER this package rebuilds from a TLV certificate differs from what
// was actually signed, byte-for-byte, breaking signature verification.
func utf8Attr(oid asn1.ObjectIdentifier, s string) pkix.AttributeTypeAndValue {
	return pkix.AttributeTypeAndValue{
		Type:  oid,
		Value: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagUTF8String, Bytes: []byte(s)},
	}
}

func marshalRDNSequence(atvs []pkix.AttributeTypeAndValue) ([]byte, error) {
	rdnSeq := make(pkix.RDNSequence, 0, len(atvs))
	for _, atv := range atvs {
		rdnSeq = append(rdnSeq, pkix.RelativeDistinguishedNameSET{atv})
	}
	return asn1.Marshal(rdnSeq)
}

// marshalKeyUsage encodes a plain KeyUsage bitmask (as produced by
// uint16(x509.KeyUsage), the same value this package writes into the TLV
// KeyUsage field in encodeExtensions) into the RFC 5280 KeyUsage extension's
// ASN.1 BIT STRING encoding. crypto/x509's own KeyUsage bit constants are
// numbered to match the named bits of that BIT STRING (bit i of the Go
// integer <-> bit i counting from the most significant bit of the DER
// content, per asn1.BitString.At), so encoding requires bit-reversal within
// each content byte.
func marshalKeyUsage(v uint16) ([]byte, error) {
	b := [2]byte{reverseBits8(byte(v)), reverseBits8(byte(v >> 8))}
	// DER requires the minimal number of bits: trailing zero bits after the
	// last set bit are dropped (not just trailing all-zero bytes).
	lastSet := -1
	for p := range 16 {
		if (b[p/8]>>uint(7-p%8))&1 != 0 {
			lastSet = p
		}
	}
	bitLen := lastSet + 1
	numBytes := (bitLen + 7) / 8
	bits := asn1.BitString{Bytes: b[:numBytes], BitLength: bitLen}
	return asn1.Marshal(bits)
}

func reverseBits8(b byte) byte {
	b = (b&0xF0)>>4 | (b&0x0F)<<4
	b = (b&0xCC)>>2 | (b&0x33)<<2
	b = (b&0xAA)>>1 | (b&0x55)<<1
	return b
}
