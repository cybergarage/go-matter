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
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// AttestationTrustStore holds the trust anchors device attestation is
// verified against (6.2.3. Device Attestation Procedure): the Product
// Attestation Authorities (PAAs) a DAC may chain to, and the certificates
// of the keys which sign Certification Declarations.
type AttestationTrustStore interface {
	// PAAs returns the trusted PAA certificates.
	PAAs() []*x509.Certificate
	// CDSigningCertificates returns the trusted Certification Declaration
	// signing certificates.
	CDSigningCertificates() []*x509.Certificate
}

type attestationTrustStore struct {
	paas []*x509.Certificate
	cds  []*x509.Certificate
}

// NewAttestationTrustStore returns an AttestationTrustStore of the given
// PAA and Certification Declaration signing certificates.
func NewAttestationTrustStore(paas, cdSigners []*x509.Certificate) AttestationTrustStore {
	return &attestationTrustStore{
		paas: append([]*x509.Certificate(nil), paas...),
		cds:  append([]*x509.Certificate(nil), cdSigners...),
	}
}

func (s *attestationTrustStore) PAAs() []*x509.Certificate {
	return append([]*x509.Certificate(nil), s.paas...)
}

func (s *attestationTrustStore) CDSigningCertificates() []*x509.Certificate {
	return append([]*x509.Certificate(nil), s.cds...)
}

// MergeAttestationTrustStores returns a store which trusts every anchor of
// the given stores; nil stores are skipped and duplicates are dropped.
func MergeAttestationTrustStores(stores ...AttestationTrustStore) AttestationTrustStore {
	var paas, cds []*x509.Certificate
	for _, s := range stores {
		if s == nil {
			continue
		}
		paas = appendUniqueCertificates(paas, s.PAAs()...)
		cds = appendUniqueCertificates(cds, s.CDSigningCertificates()...)
	}
	return NewAttestationTrustStore(paas, cds)
}

func appendUniqueCertificates(list []*x509.Certificate, certs ...*x509.Certificate) []*x509.Certificate {
	for _, c := range certs {
		dup := false
		for _, have := range list {
			if bytes.Equal(have.Raw, c.Raw) {
				dup = true
				break
			}
		}
		if !dup {
			list = append(list, c)
		}
	}
	return list
}

// ParseAttestationTrustStore builds a store from DER- or PEM-encoded
// certificates. A self-signed CA certificate is taken for a PAA; any other
// certificate for a Certification Declaration signing certificate.
func ParseAttestationTrustStore(certs ...[]byte) (AttestationTrustStore, error) {
	var paas, cds []*x509.Certificate
	for _, b := range certs {
		parsed, err := parseCertificates(b)
		if err != nil {
			return nil, err
		}
		for _, cert := range parsed {
			if isPAA(cert) {
				paas = appendUniqueCertificates(paas, cert)
			} else {
				cds = appendUniqueCertificates(cds, cert)
			}
		}
	}
	return NewAttestationTrustStore(paas, cds), nil
}

// LoadAttestationTrustStore reads every .der, .pem, .crt and .cer file in
// dir, as ParseAttestationTrustStore does; other files are ignored.
func LoadAttestationTrustStore(dir string) (AttestationTrustStore, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("credentials: read the attestation trust store: %w", err)
	}
	var certs [][]byte
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		switch strings.ToLower(filepath.Ext(e.Name())) {
		case ".der", ".pem", ".crt", ".cer":
		default:
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("credentials: read the attestation trust store: %w", err)
		}
		certs = append(certs, b)
	}
	store, err := ParseAttestationTrustStore(certs...)
	if err != nil {
		return nil, fmt.Errorf("credentials: %s: %w", dir, err)
	}
	return store, nil
}

func parseCertificates(b []byte) ([]*x509.Certificate, error) {
	if !bytes.Contains(b, []byte("-----BEGIN")) {
		cert, err := x509.ParseCertificate(b)
		if err != nil {
			return nil, fmt.Errorf("parse a certificate: %w", err)
		}
		return []*x509.Certificate{cert}, nil
	}
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, b = pem.Decode(b)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse a certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, errors.New("no certificate in the PEM data")
	}
	return certs, nil
}

// isPAA reports whether cert is a self-signed CA certificate.
func isPAA(cert *x509.Certificate) bool {
	if !cert.BasicConstraintsValid || !cert.IsCA {
		return false
	}
	return bytes.Equal(cert.RawIssuer, cert.RawSubject) && cert.CheckSignatureFrom(cert) == nil
}
