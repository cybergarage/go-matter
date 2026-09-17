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

// Package chipcert implements the Matter Certificate ("CHIPCert") compact TLV
// encoding — a TLV representation of an X.509 certificate used on the wire by
// the Operational Credentials cluster (CertificateChainRequest/AddNOC/
// AddTrustedRootCertificate responses and commands) and embedded in CASE
// Sigma2/Sigma3 messages.
//
// Reference: Matter Core Spec Appendix "Compact TLV Encoding of Matter
// Certificates", and the official C++ reference implementation
// (https://github.com/project-chip/connectedhomeip):
// src/credentials/CHIPCert.h (TLV tag / DN attribute enum values),
// src/credentials/CHIPCertFromX509.cpp and CHIPCertToX509.cpp (the conversion
// this package mirrors), and src/lib/asn1/gen_asn1oid.py (the OID enum table).
package chipcert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/cybergarage/go-matter/matter/encoding/tlv"
)

// Matter Certificate TLV tag numbers. CHIPCert.h.
const (
	tagSerialNumber            = 1
	tagSignatureAlgorithm      = 2
	tagIssuer                  = 3
	tagNotBefore               = 4
	tagNotAfter                = 5
	tagSubject                 = 6
	tagPublicKeyAlgorithm      = 7
	tagEllipticCurveIdentifier = 8
	tagEllipticCurvePublicKey  = 9
	tagExtensions              = 10
	tagECDSASignature          = 11

	tagExtBasicConstraints       = 1
	tagExtKeyUsage               = 2
	tagExtExtendedKeyUsage       = 3
	tagExtSubjectKeyIdentifier   = 4
	tagExtAuthorityKeyIdentifier = 5

	tagBasicConstraintsIsCA              = 1
	tagBasicConstraintsPathLenConstraint = 2
)

// DN attribute-type OID enum values. These double as the TLV context-tag
// number used for each RDN element (optionally OR'd with printableStringFlag).
// gen_asn1oid.py "AttributeType" category.
const (
	oidEnumCommonName              = 1
	oidEnumMatterNodeID            = 17
	oidEnumMatterFirmwareSigningID = 18
	oidEnumMatterICACID            = 19
	oidEnumMatterRCACID            = 20
	oidEnumMatterFabricID          = 21
	oidEnumMatterCASEAuthTag       = 22

	printableStringFlag = 0x80
	attrTypeMask        = 0x7F
)

// PubKeyAlgo / SigAlgo / EllipticCurve OID enum values. Matter only defines a
// single value for each, corresponding to NIST P-256 ECDSA-with-SHA256.
const (
	pubKeyAlgoECPublicKey  = 1
	sigAlgoECDSAWithSHA256 = 1
	curvePrime256v1        = 1
)

// KeyPurpose OID enum values, used for the ExtendedKeyUsage extension array.
const (
	keyPurposeServerAuth = 1
	keyPurposeClientAuth = 2
)

// Well-known ASN.1 object identifiers used by CHIPCert DN attributes,
// mirroring matter/protocol/case/crypto.go's matterNodeIDOID/matterFabricIDOID
// (enterprise OID 1.3.6.1.4.1.37244.1.{1..6}).
var (
	oidCommonName              = asn1.ObjectIdentifier{2, 5, 4, 3}
	oidMatterNodeID            = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37244, 1, 1}
	oidMatterFirmwareSigningID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37244, 1, 2}
	oidMatterICACID            = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37244, 1, 3}
	oidMatterRCACID            = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37244, 1, 4}
	oidMatterFabricID          = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37244, 1, 5}
	oidMatterCASEAuthTag       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37244, 1, 6}

	oidPublicKeyECDSA        = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidSigECDSAWithSHA256    = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidExtKeyUsageServerAuth = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	oidExtKeyUsageClientAuth = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
)

// chipEpoch is the Matter epoch (2000-01-01T00:00:00Z) used for NotBefore/NotAfter.
var chipEpoch = time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)

func timeToChipEpoch(t time.Time) uint32 {
	d := t.Unix() - chipEpoch.Unix()
	if d < 0 {
		return 0
	}
	return uint32(d)
}

func chipEpochToTime(v uint32) time.Time {
	return chipEpoch.Add(time.Duration(v) * time.Second)
}

// DERToTLV converts a DER-encoded X.509 certificate (as produced by
// crypto/x509.CreateCertificate, using P-256 ECDSA-with-SHA256, a subset of
// extensions, and the Matter custom-OID DN attribute convention already used
// in this repo — see matter/protocol/case/crypto.go's matterUint64RDN) into
// compact Matter-TLV CHIPCert bytes.
func DERToTLV(der []byte) ([]byte, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("chipcert: parse DER certificate: %w", err)
	}

	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("chipcert: unsupported public key type %T", cert.PublicKey)
	}
	if cert.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		return nil, fmt.Errorf("chipcert: unsupported signature algorithm %v", cert.SignatureAlgorithm)
	}
	rawSig, err := derSignatureToRaw(cert.Signature)
	if err != nil {
		return nil, fmt.Errorf("chipcert: convert signature: %w", err)
	}

	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	if err := enc.PutOctet(tlv.NewContextTag(tagSerialNumber), asn1IntegerBytes(cert.SerialNumber)); err != nil {
		return nil, err
	}
	enc.PutUnsigned1(tlv.NewContextTag(tagSignatureAlgorithm), sigAlgoECDSAWithSHA256)
	if err := encodeDN(enc, tagIssuer, cert.Issuer.Names); err != nil {
		return nil, err
	}
	enc.PutUnsigned4(tlv.NewContextTag(tagNotBefore), timeToChipEpoch(cert.NotBefore))
	enc.PutUnsigned4(tlv.NewContextTag(tagNotAfter), timeToChipEpoch(cert.NotAfter))
	if err := encodeDN(enc, tagSubject, cert.Subject.Names); err != nil {
		return nil, err
	}
	enc.PutUnsigned1(tlv.NewContextTag(tagPublicKeyAlgorithm), pubKeyAlgoECPublicKey)
	enc.PutUnsigned1(tlv.NewContextTag(tagEllipticCurveIdentifier), curvePrime256v1)
	pubKeyBytes := elliptic.Marshal(pub.Curve, pub.X, pub.Y)
	if err := enc.PutOctet(tlv.NewContextTag(tagEllipticCurvePublicKey), pubKeyBytes); err != nil {
		return nil, err
	}
	if err := encodeExtensions(enc, cert); err != nil {
		return nil, err
	}
	if err := enc.PutOctet(tlv.NewContextTag(tagECDSASignature), rawSig); err != nil {
		return nil, err
	}
	if err := enc.EndContainer(); err != nil {
		return nil, err
	}
	return enc.Bytes(), nil
}

func asn1IntegerBytes(n *big.Int) []byte {
	b, err := asn1.Marshal(n)
	if err != nil {
		// n is always a well-formed *big.Int from a parsed certificate; this cannot fail.
		return n.Bytes()
	}
	// asn1.Marshal(*big.Int) returns a full INTEGER TLV (tag 0x02, length, content);
	// CHIPCert's SerialNumber field only wants the content (BER integer bytes).
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(b, &raw); err != nil {
		return n.Bytes()
	}
	return raw.Bytes
}

func encodeDN(enc tlv.Encoder, tag uint8, atvs []pkix.AttributeTypeAndValue) error {
	enc.BeginList(tlv.NewContextTag(tag))
	for _, atv := range atvs {
		if err := encodeRDN(enc, atv); err != nil {
			return err
		}
	}
	return enc.EndContainer()
}

func encodeRDN(enc tlv.Encoder, atv pkix.AttributeTypeAndValue) error {
	if oidEnum, ok := matterOIDEnum(atv.Type); ok {
		s, ok := atv.Value.(string)
		if !ok {
			return fmt.Errorf("chipcert: Matter DN attribute value is not a string")
		}
		v, err := hexRDNToUint64(s)
		if err != nil {
			return fmt.Errorf("chipcert: decode Matter DN attribute: %w", err)
		}
		return enc.PutUnsigned(tlv.NewContextTag(uint8(oidEnum)), v)
	}
	if atv.Type.Equal(oidCommonName) {
		s, ok := atv.Value.(string)
		if !ok {
			return fmt.Errorf("chipcert: CommonName DN attribute value is not a string")
		}
		return enc.PutUTF8(tlv.NewContextTag(oidEnumCommonName), s)
	}
	// Unsupported/unknown DN attribute type: omitted from the compact TLV
	// encoding. Only the well-known Matter and CommonName attributes this
	// repo's certificate authority generates are required to round-trip
	// losslessly; foreign attributes on third-party certificates (e.g. a real
	// device's DAC/PAI) are not needed for the pragmatic, signature-only
	// attestation verification performed by this codebase (see
	// matter/credentials/attestation.go).
	return nil
}

func matterOIDEnum(oid asn1.ObjectIdentifier) (int, bool) {
	switch {
	case oid.Equal(oidMatterNodeID):
		return oidEnumMatterNodeID, true
	case oid.Equal(oidMatterFirmwareSigningID):
		return oidEnumMatterFirmwareSigningID, true
	case oid.Equal(oidMatterICACID):
		return oidEnumMatterICACID, true
	case oid.Equal(oidMatterRCACID):
		return oidEnumMatterRCACID, true
	case oid.Equal(oidMatterFabricID):
		return oidEnumMatterFabricID, true
	case oid.Equal(oidMatterCASEAuthTag):
		return oidEnumMatterCASEAuthTag, true
	default:
		return 0, false
	}
}

func matterOIDForEnum(oidEnum int) (asn1.ObjectIdentifier, bool) {
	switch oidEnum {
	case oidEnumMatterNodeID:
		return oidMatterNodeID, true
	case oidEnumMatterFirmwareSigningID:
		return oidMatterFirmwareSigningID, true
	case oidEnumMatterICACID:
		return oidMatterICACID, true
	case oidEnumMatterRCACID:
		return oidMatterRCACID, true
	case oidEnumMatterFabricID:
		return oidMatterFabricID, true
	case oidEnumMatterCASEAuthTag:
		return oidMatterCASEAuthTag, true
	default:
		return nil, false
	}
}

// hexRDNToUint64 and uint64ToHexRDN match the DER-side representation this
// repo's certificate authority and matterUint64RDN (case/crypto.go) already
// use for Matter numeric DN attributes: a 16-character uppercase hex string
// (big-endian uint64), rather than a native ASN.1 INTEGER.
func hexRDNToUint64(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	b, err := hex.DecodeString(s)
	if err != nil {
		return 0, err
	}
	if len(b) != 8 {
		return 0, fmt.Errorf("unexpected hex length %d", len(b))
	}
	return binary.BigEndian.Uint64(b), nil
}

func uint64ToHexRDN(v uint64) string {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return strings.ToUpper(hex.EncodeToString(b))
}

func encodeExtensions(enc tlv.Encoder, cert *x509.Certificate) error {
	enc.BeginList(tlv.NewContextTag(tagExtensions))
	if cert.BasicConstraintsValid {
		enc.BeginStructure(tlv.NewContextTag(tagExtBasicConstraints))
		enc.PutBool(tlv.NewContextTag(tagBasicConstraintsIsCA), cert.IsCA)
		if cert.MaxPathLen > 0 || (cert.MaxPathLen == 0 && cert.MaxPathLenZero) {
			enc.PutUnsigned1(tlv.NewContextTag(tagBasicConstraintsPathLenConstraint), uint8(cert.MaxPathLen))
		}
		if err := enc.EndContainer(); err != nil {
			return err
		}
	}
	if cert.KeyUsage != 0 {
		enc.PutUnsigned2(tlv.NewContextTag(tagExtKeyUsage), uint16(cert.KeyUsage))
	}
	if len(cert.ExtKeyUsage) > 0 {
		enc.BeginArray(tlv.NewContextTag(tagExtExtendedKeyUsage))
		for _, ku := range cert.ExtKeyUsage {
			var v uint8
			switch ku {
			case x509.ExtKeyUsageServerAuth:
				v = keyPurposeServerAuth
			case x509.ExtKeyUsageClientAuth:
				v = keyPurposeClientAuth
			default:
				continue
			}
			enc.PutUnsigned1(tlv.NewAnonymousTag(), v)
		}
		if err := enc.EndContainer(); err != nil {
			return err
		}
	}
	if len(cert.SubjectKeyId) > 0 {
		if err := enc.PutOctet(tlv.NewContextTag(tagExtSubjectKeyIdentifier), cert.SubjectKeyId); err != nil {
			return err
		}
	}
	if len(cert.AuthorityKeyId) > 0 {
		if err := enc.PutOctet(tlv.NewContextTag(tagExtAuthorityKeyIdentifier), cert.AuthorityKeyId); err != nil {
			return err
		}
	}
	return enc.EndContainer()
}

// derSignature mirrors the RFC 5480 / X9.62 ECDSA-Sig-Value ASN.1 structure
// used inside an X.509 certificate's signatureValue BIT STRING.
type derSignature struct {
	R, S *big.Int
}

func derSignatureToRaw(der []byte) ([]byte, error) {
	var sig derSignature
	if _, err := asn1.Unmarshal(der, &sig); err != nil {
		return nil, err
	}
	raw := make([]byte, 64)
	sig.R.FillBytes(raw[:32])
	sig.S.FillBytes(raw[32:])
	return raw, nil
}

func rawSignatureToDER(raw []byte) ([]byte, error) {
	if len(raw) != 64 {
		return nil, fmt.Errorf("chipcert: invalid raw signature length %d", len(raw))
	}
	r := new(big.Int).SetBytes(raw[:32])
	s := new(big.Int).SetBytes(raw[32:64])
	return asn1.Marshal(derSignature{R: r, S: s})
}
