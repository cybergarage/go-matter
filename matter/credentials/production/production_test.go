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

package production

import (
	"bytes"
	"crypto/x509"
	"testing"
)

func TestBundledPAAsAreSelfSignedCAs(t *testing.T) {
	paas := PAAs()
	if len(paas) < 50 {
		t.Fatalf("PAAs() = %d certificates, want the DCL's", len(paas))
	}
	for _, b := range paas {
		cert, err := x509.ParseCertificate(b)
		if err != nil {
			t.Fatalf("a bundled PAA does not parse: %v", err)
		}
		if !cert.IsCA || !bytes.Equal(cert.RawIssuer, cert.RawSubject) {
			t.Errorf("PAA %q is not a self-signed CA", cert.Subject.CommonName)
		}
		if cert.Subject.CommonName == "Matter Certification and Testing CA" {
			t.Errorf("the CD signing CA is bundled as a PAA")
		}
	}
}

func TestBundledCDSigningCertificatesAreTheCSAs(t *testing.T) {
	cds := CDSigningCertificates()
	if len(cds) != 5 {
		t.Fatalf("CDSigningCertificates() = %d certificates, want 5", len(cds))
	}
	for _, b := range cds {
		cert, err := x509.ParseCertificate(b)
		if err != nil {
			t.Fatal(err)
		}
		if len(cert.Subject.Organization) != 1 || cert.Subject.Organization[0] != "CSA" {
			t.Errorf("CD signing certificate %q is not the CSA's", cert.Subject.CommonName)
		}
	}
}
