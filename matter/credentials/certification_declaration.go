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
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/cybergarage/go-matter/matter/encoding/tlv"
)

// CertificationType is the certification_type of a Certification
// Declaration (6.3.1. Certification Declaration format).
type CertificationType uint8

const (
	// CertificationTypeDevelopmentAndTest marks a declaration for
	// development and testing, such as the Matter SDK's example one.
	CertificationTypeDevelopmentAndTest CertificationType = 0
	// CertificationTypeProvisional marks a provisionally certified product.
	CertificationTypeProvisional CertificationType = 1
	// CertificationTypeOfficial marks an officially certified product.
	CertificationTypeOfficial CertificationType = 2
)

// CertificationDeclaration is the content of a Certification Declaration
// (6.3.1. Certification Declaration format): the products of a vendor which
// the Connectivity Standards Alliance certified.
type CertificationDeclaration struct {
	FormatVersion       uint16
	VendorID            uint16
	ProductIDs          []uint16
	DeviceTypeID        uint32
	CertificateID       string
	SecurityLevel       uint8
	SecurityInformation uint16
	VersionNumber       uint16
	CertificationType   CertificationType
	// DACOriginVendorID and DACOriginProductID, when present, name the
	// vendor and the product whose DAC the certified product carries.
	DACOriginVendorID  uint16
	DACOriginProductID uint16
	HasDACOrigin       bool
	// AuthorizedPAAs, when not empty, lists the subject key IDs of the PAAs
	// which may anchor the product's DAC.
	AuthorizedPAAs [][]byte
}

// Certification Declaration TLV field tags (6.3.1).
const (
	tagCDFormatVersion       = 0
	tagCDVendorID            = 1
	tagCDProductIDArray      = 2
	tagCDDeviceTypeID        = 3
	tagCDCertificateID       = 4
	tagCDSecurityLevel       = 5
	tagCDSecurityInformation = 6
	tagCDVersionNumber       = 7
	tagCDCertificationType   = 8
	tagCDDACOriginVendorID   = 9
	tagCDDACOriginProductID  = 10
	tagCDAuthorizedPAAList   = 11

	// certificationDeclarationFormatVersion is the only format_version
	// this package knows the schema of.
	certificationDeclarationFormatVersion = 1
	// certificateIDLength is the length of certificate_id, such as
	// "ZIG20141ZB330001-24" (6.3.1).
	certificateIDLength = 19
	// maxCDProductIDs is the largest product_id_array (6.3.1).
	maxCDProductIDs = 100
)

var (
	oidCMSSignedData      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidCMSData            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidDigestSHA256       = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSignatureECDSAWith = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
)

// ErrInvalidCertificationDeclaration is wrapped by every error about a
// malformed or untrusted Certification Declaration.
var ErrInvalidCertificationDeclaration = errors.New("credentials: invalid Certification Declaration")

type cmsContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0"`
}

type cmsSignedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	EncapContentInfo cmsEncapsulatedContentInfo
	Certificates     asn1.RawValue   `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue   `asn1:"optional,tag:1"`
	SignerInfos      []cmsSignerInfo `asn1:"set"`
}

type cmsEncapsulatedContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     []byte `asn1:"explicit,optional,tag:0"`
}

type cmsSignerInfo struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	UnsignedAttrs      asn1.RawValue `asn1:"optional,tag:1"`
}

// SignedCertificationDeclaration is a Certification Declaration as a
// device sends it: CMS SignedData over the declaration's TLV, signed by a
// Certification Declaration signing key (6.3.2. Certification Declaration
// signing).
type SignedCertificationDeclaration struct {
	// Content is the TLV-encoded declaration the signature covers.
	Content []byte
	// SignerKeyID is the subject key ID of the signing certificate.
	SignerKeyID []byte
	signature   []byte
}

// ParseSignedCertificationDeclaration decodes the CMS envelope of a
// Certification Declaration without verifying it.
func ParseSignedCertificationDeclaration(der []byte) (*SignedCertificationDeclaration, error) {
	var ci cmsContentInfo
	if rest, err := asn1.Unmarshal(der, &ci); err != nil || len(rest) != 0 {
		return nil, fmt.Errorf("%w: not a CMS ContentInfo", ErrInvalidCertificationDeclaration)
	}
	if !ci.ContentType.Equal(oidCMSSignedData) {
		return nil, fmt.Errorf("%w: content type %v is not SignedData", ErrInvalidCertificationDeclaration, ci.ContentType)
	}
	var sd cmsSignedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, fmt.Errorf("%w: SignedData: %w", ErrInvalidCertificationDeclaration, err)
	}
	if !sd.EncapContentInfo.EContentType.Equal(oidCMSData) || len(sd.EncapContentInfo.EContent) == 0 {
		return nil, fmt.Errorf("%w: no encapsulated declaration", ErrInvalidCertificationDeclaration)
	}
	if len(sd.SignerInfos) != 1 {
		return nil, fmt.Errorf("%w: %d signers, want 1", ErrInvalidCertificationDeclaration, len(sd.SignerInfos))
	}
	si := sd.SignerInfos[0]
	// The signer is identified by its subject key identifier, the [0]
	// alternative of SignerIdentifier.
	if si.SID.Class != asn1.ClassContextSpecific || si.SID.Tag != 0 || len(si.SID.Bytes) == 0 {
		return nil, fmt.Errorf("%w: the signer is not identified by a subject key ID", ErrInvalidCertificationDeclaration)
	}
	if !si.DigestAlgorithm.Algorithm.Equal(oidDigestSHA256) || !si.SignatureAlgorithm.Algorithm.Equal(oidSignatureECDSAWith) {
		return nil, fmt.Errorf("%w: the signature is not ECDSA with SHA-256", ErrInvalidCertificationDeclaration)
	}
	if len(si.SignedAttrs.FullBytes) != 0 {
		return nil, fmt.Errorf("%w: signed attributes are not supported", ErrInvalidCertificationDeclaration)
	}
	return &SignedCertificationDeclaration{
		Content:     append([]byte(nil), sd.EncapContentInfo.EContent...),
		SignerKeyID: append([]byte(nil), si.SID.Bytes...),
		signature:   append([]byte(nil), si.Signature...),
	}, nil
}

// Verify checks the declaration's signature with the signing certificate,
// whose subject key ID must be the declaration's SignerKeyID.
func (cd *SignedCertificationDeclaration) Verify(signer *x509.Certificate) error {
	if !bytes.Equal(signer.SubjectKeyId, cd.SignerKeyID) {
		return fmt.Errorf("%w: the signing certificate is not the declaration's signer", ErrInvalidCertificationDeclaration)
	}
	pub, ok := signer.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("%w: the signing key is not ECDSA", ErrInvalidCertificationDeclaration)
	}
	digest := sha256.Sum256(cd.Content)
	if !ecdsa.VerifyASN1(pub, digest[:], cd.signature) {
		return fmt.Errorf("%w: the signature does not verify", ErrInvalidCertificationDeclaration)
	}
	return nil
}

// ParseCertificationDeclaration decodes the TLV content of a Certification
// Declaration (6.3.1).
func ParseCertificationDeclaration(content []byte) (*CertificationDeclaration, error) {
	dec := tlv.NewDecoderWithBytes(content)
	if !dec.Next() || !dec.Element().Type().IsStructure() {
		return nil, fmt.Errorf("%w: the content is not a TLV structure", ErrInvalidCertificationDeclaration)
	}
	cd := &CertificationDeclaration{}
	seen := map[uint8]bool{}
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			break
		}
		ct, ok := elem.Tag().(tlv.ContextTag)
		if !ok {
			return nil, fmt.Errorf("%w: unexpected tag %v", ErrInvalidCertificationDeclaration, elem.Tag())
		}
		if seen[uint8(ct.ContextNumber())] {
			return nil, fmt.Errorf("%w: field %d is repeated", ErrInvalidCertificationDeclaration, ct.ContextNumber())
		}
		seen[uint8(ct.ContextNumber())] = true
		var err error
		switch ct.ContextNumber() {
		case tagCDFormatVersion:
			cd.FormatVersion, err = cdUnsigned2(elem)
		case tagCDVendorID:
			cd.VendorID, err = cdUnsigned2(elem)
		case tagCDProductIDArray:
			cd.ProductIDs, err = cdProductIDs(dec, elem)
		case tagCDDeviceTypeID:
			v, ok := elem.Unsigned()
			if !ok || v > 0xFFFFFFFF {
				err = errors.New("device_type_id is not a 32-bit integer")
			}
			cd.DeviceTypeID = uint32(v)
		case tagCDCertificateID:
			if cd.CertificateID, ok = elem.UTF8(); !ok || len(cd.CertificateID) != certificateIDLength {
				err = fmt.Errorf("certificate_id is not a %d-character string", certificateIDLength)
			}
		case tagCDSecurityLevel:
			v, ok := elem.Unsigned()
			if !ok || v > 0xFF {
				err = errors.New("security_level is not an 8-bit integer")
			}
			cd.SecurityLevel = uint8(v)
		case tagCDSecurityInformation:
			cd.SecurityInformation, err = cdUnsigned2(elem)
		case tagCDVersionNumber:
			cd.VersionNumber, err = cdUnsigned2(elem)
		case tagCDCertificationType:
			v, ok := elem.Unsigned()
			if !ok || v > uint64(CertificationTypeOfficial) {
				err = errors.New("certification_type is not a known type")
			}
			cd.CertificationType = CertificationType(v)
		case tagCDDACOriginVendorID:
			cd.DACOriginVendorID, err = cdUnsigned2(elem)
		case tagCDDACOriginProductID:
			cd.DACOriginProductID, err = cdUnsigned2(elem)
		case tagCDAuthorizedPAAList:
			cd.AuthorizedPAAs, err = cdAuthorizedPAAs(dec, elem)
		default:
			err = fmt.Errorf("unknown field %d", ct.ContextNumber())
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidCertificationDeclaration, err)
		}
	}
	if err := dec.Error(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidCertificationDeclaration, err)
	}
	// Fields 0 to 8 are mandatory (6.3.1).
	for tag := uint8(tagCDFormatVersion); tag <= tagCDCertificationType; tag++ {
		if !seen[tag] {
			return nil, fmt.Errorf("%w: mandatory field %d is missing", ErrInvalidCertificationDeclaration, tag)
		}
	}
	if cd.FormatVersion != certificationDeclarationFormatVersion {
		return nil, fmt.Errorf("%w: format_version %d is not %d", ErrInvalidCertificationDeclaration, cd.FormatVersion, certificationDeclarationFormatVersion)
	}
	if len(cd.ProductIDs) == 0 || len(cd.ProductIDs) > maxCDProductIDs {
		return nil, fmt.Errorf("%w: product_id_array has %d entries, not 1 to %d", ErrInvalidCertificationDeclaration, len(cd.ProductIDs), maxCDProductIDs)
	}
	if seen[tagCDDACOriginVendorID] != seen[tagCDDACOriginProductID] {
		return nil, fmt.Errorf("%w: dac_origin_vendor_id and dac_origin_product_id must be present together", ErrInvalidCertificationDeclaration)
	}
	cd.HasDACOrigin = seen[tagCDDACOriginVendorID]
	return cd, nil
}

func cdUnsigned2(elem tlv.Element) (uint16, error) {
	v, ok := elem.Unsigned()
	if !ok || v > 0xFFFF {
		return 0, fmt.Errorf("%v is not a 16-bit integer", elem.Tag())
	}
	return uint16(v), nil
}

// cdProductIDs reads the members of product_id_array, whose array element
// the decoder has just returned.
func cdProductIDs(dec tlv.Decoder, array tlv.Element) ([]uint16, error) {
	if !array.Type().IsArray() {
		return nil, errors.New("product_id_array is not an array")
	}
	var ids []uint16
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			return ids, nil
		}
		id, err := cdUnsigned2(elem)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return nil, errors.New("product_id_array is not terminated")
}

// cdAuthorizedPAAs reads the members of authorized_paa_list, subject key
// IDs of 20 bytes.
func cdAuthorizedPAAs(dec tlv.Decoder, array tlv.Element) ([][]byte, error) {
	if !array.Type().IsArray() {
		return nil, errors.New("authorized_paa_list is not an array")
	}
	var ids [][]byte
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			return ids, nil
		}
		b, ok := elem.Bytes()
		if !ok || len(b) != 20 {
			return nil, errors.New("authorized_paa_list holds an entry which is not a 20-byte key ID")
		}
		ids = append(ids, b)
	}
	return nil, errors.New("authorized_paa_list is not terminated")
}
