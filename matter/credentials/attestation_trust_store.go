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

// ParseAttestationTrustStore builds a store from DER- or PEM-encoded PAA
// certificates and Certification Declaration signing certificates. The two
// are given apart, since a test CD signing certificate is a self-signed CA
// just like a PAA.
func ParseAttestationTrustStore(paas, cdSigners [][]byte) (AttestationTrustStore, error) {
	parsedPAAs, err := parseCertificateList(paas)
	if err != nil {
		return nil, fmt.Errorf("credentials: PAA: %w", err)
	}
	parsedCDs, err := parseCertificateList(cdSigners)
	if err != nil {
		return nil, fmt.Errorf("credentials: CD signing certificate: %w", err)
	}
	return NewAttestationTrustStore(parsedPAAs, parsedCDs), nil
}

func parseCertificateList(list [][]byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for _, b := range list {
		parsed, err := parseCertificates(b)
		if err != nil {
			return nil, err
		}
		certs = appendUniqueCertificates(certs, parsed...)
	}
	return certs, nil
}

// LoadAttestationTrustStore reads the PAA certificates in paaDir and the
// Certification Declaration signing certificates in cdDir, as chip-tool's
// --paa-trust-store-path and --cd-trust-store-path do. Either directory may
// be empty to read none. Every .der, .pem, .crt and .cer file is read;
// other files are ignored.
func LoadAttestationTrustStore(paaDir, cdDir string) (AttestationTrustStore, error) {
	paas, err := readCertificateFiles(paaDir)
	if err != nil {
		return nil, err
	}
	cds, err := readCertificateFiles(cdDir)
	if err != nil {
		return nil, err
	}
	store, err := ParseAttestationTrustStore(paas, cds)
	if err != nil {
		return nil, err
	}
	return store, nil
}

func readCertificateFiles(dir string) ([][]byte, error) {
	if dir == "" {
		return nil, nil
	}
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
	return certs, nil
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
