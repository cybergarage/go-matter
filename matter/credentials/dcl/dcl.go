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

// Package dcl reads the trust anchors of device attestation from the
// Distributed Compliance Ledger (DCL) of the Connectivity Standards
// Alliance over its REST API: the approved Product Attestation Authorities
// and the Certification Declaration signing certificates. It follows the
// Matter SDK's credentials/fetch_paa_certs_from_dcl.py.
//
// go-matter does not reach the network for these by itself: the
// credentials/production package bundles a snapshot. Use this package to
// refresh that snapshot, or to give a Commissioner newer anchors.
package dcl

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const (
	// MainNetURL is the REST endpoint of the production DCL.
	MainNetURL = "https://on.dcl.csa-iot.org"
	// TestNetURL is the REST endpoint of the test DCL.
	TestNetURL = "https://on.test-net.dcl.csa-iot.org"

	// matterCertificationCASubject and matterCertificationCAKeyID name the
	// "Matter Certification and Testing CA", the root which issues the
	// Certification Declaration signing certificates. It is a DCL root
	// certificate but not a PAA.
	matterCertificationCASubject = "MFIxDDAKBgNVBAoMA0NTQTEsMCoGA1UEAwwjTWF0dGVyIENlcnRpZmljYXRpb24gYW5kIFRlc3RpbmcgQ0ExFDASBgorBgEEAYKifAIBDARDNUEw"
	matterCertificationCAKeyID   = "97:E4:69:D0:C5:04:14:C2:6F:C7:01:F7:7E:94:77:39:09:8D:F6:A5"
)

// Client reads certificates from a DCL REST endpoint.
type Client struct {
	baseURL string
	http    *http.Client
}

// ClientOption configures a Client.
type ClientOption func(*Client)

// WithHTTPClient sets the HTTP client requests are sent with.
func WithHTTPClient(c *http.Client) ClientOption {
	return func(cl *Client) {
		cl.http = c
	}
}

// NewClient returns a Client of the REST endpoint baseURL, such as
// MainNetURL.
func NewClient(baseURL string, opts ...ClientOption) *Client {
	c := &Client{baseURL: strings.TrimRight(baseURL, "/"), http: http.DefaultClient}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

type certificateID struct {
	Subject      string `json:"subject"`
	SubjectKeyID string `json:"subjectKeyId"`
}

// PAAs returns the approved root certificates of the ledger, which are the
// PAAs, without the Matter Certification and Testing CA.
func (c *Client) PAAs(ctx context.Context) ([]*x509.Certificate, error) {
	var resp struct {
		ApprovedRootCertificates struct {
			Certs []certificateID `json:"certs"`
		} `json:"approvedRootCertificates"`
	}
	if err := c.getJSON(ctx, "/dcl/pki/root-certificates", &resp); err != nil {
		return nil, err
	}
	var ids []certificateID
	for _, id := range resp.ApprovedRootCertificates.Certs {
		if id.Subject == matterCertificationCASubject && id.SubjectKeyID == matterCertificationCAKeyID {
			continue
		}
		ids = append(ids, id)
	}
	return c.certificates(ctx, ids)
}

// CDSigningCertificates returns the certificates the Matter Certification
// and Testing CA issued, which sign Certification Declarations.
func (c *Client) CDSigningCertificates(ctx context.Context) ([]*x509.Certificate, error) {
	var resp struct {
		ChildCertificates struct {
			CertIDs []certificateID `json:"certIds"`
		} `json:"childCertificates"`
	}
	path := "/dcl/pki/child-certificates/" + matterCertificationCASubject + "/" + matterCertificationCAKeyID
	if err := c.getJSON(ctx, path, &resp); err != nil {
		return nil, err
	}
	return c.certificates(ctx, resp.ChildCertificates.CertIDs)
}

func (c *Client) certificates(ctx context.Context, ids []certificateID) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, 0, len(ids))
	for _, id := range ids {
		cert, err := c.certificate(ctx, id)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

func (c *Client) certificate(ctx context.Context, id certificateID) (*x509.Certificate, error) {
	var resp struct {
		ApprovedCertificates struct {
			Certs []struct {
				PEMCert string `json:"pemCert"`
			} `json:"certs"`
		} `json:"approvedCertificates"`
	}
	// The subject and the key ID go in the path as the ledger gives them,
	// as the Matter SDK's fetch script does.
	if err := c.getJSON(ctx, "/dcl/pki/certificates/"+id.Subject+"/"+id.SubjectKeyID, &resp); err != nil {
		return nil, err
	}
	if len(resp.ApprovedCertificates.Certs) == 0 {
		return nil, fmt.Errorf("dcl: no approved certificate for key ID %s", id.SubjectKeyID)
	}
	block, _ := pem.Decode([]byte(resp.ApprovedCertificates.Certs[0].PEMCert))
	if block == nil {
		return nil, fmt.Errorf("dcl: the certificate with key ID %s is not PEM", id.SubjectKeyID)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("dcl: the certificate with key ID %s: %w", id.SubjectKeyID, err)
	}
	return cert, nil
}

func (c *Client) getJSON(ctx context.Context, path string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return fmt.Errorf("dcl: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("dcl: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return fmt.Errorf("dcl: %s: %w", path, err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("dcl: %s: %s", path, resp.Status)
	}
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("dcl: %s: %w", path, err)
	}
	return nil
}

// FileName returns the name a certificate is stored under: its subject key
// ID in uppercase hex, or its SHA-256 fingerprint when it has none, with
// ".der".
func FileName(cert *x509.Certificate) string {
	if len(cert.SubjectKeyId) != 0 {
		return strings.ToUpper(hex.EncodeToString(cert.SubjectKeyId)) + ".der"
	}
	return fmt.Sprintf("%X.der", sha256Sum(cert.Raw))
}

// WriteCertificates replaces the .der files in dir with the certificates,
// DER-encoded and named by FileName. Other files are left alone.
func WriteCertificates(dir string, certs []*x509.Certificate) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("dcl: %w", err)
	}
	old, err := filepath.Glob(filepath.Join(dir, "*.der"))
	if err != nil {
		return fmt.Errorf("dcl: %w", err)
	}
	for _, f := range old {
		if err := os.Remove(f); err != nil {
			return fmt.Errorf("dcl: %w", err)
		}
	}
	seen := map[string][]byte{}
	for _, cert := range certs {
		name := FileName(cert)
		if prev, ok := seen[name]; ok {
			if bytes.Equal(prev, cert.Raw) {
				continue
			}
			return fmt.Errorf("dcl: two certificates are named %s", name)
		}
		seen[name] = cert.Raw
		if err := os.WriteFile(filepath.Join(dir, name), cert.Raw, 0o644); err != nil {
			return fmt.Errorf("dcl: %w", err)
		}
	}
	if len(seen) == 0 {
		return errors.New("dcl: no certificate to write")
	}
	return nil
}

func sha256Sum(b []byte) [32]byte {
	return sha256.Sum256(b)
}
