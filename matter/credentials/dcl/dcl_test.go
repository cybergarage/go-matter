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

package dcl

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newRoot(t *testing.T, cn string, skid byte) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(int64(skid)),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{skid, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19},
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// fakeLedger answers the DCL REST requests the client sends, in the shape
// of the ledger's responses.
func fakeLedger(t *testing.T, paas, cds []*x509.Certificate) *httptest.Server {
	t.Helper()
	byPath := map[string]*x509.Certificate{}
	id := func(c *x509.Certificate) map[string]string {
		subject := c.Subject.CommonName + "-subject"
		keyID := FileName(c)
		byPath["/dcl/pki/certificates/"+subject+"/"+keyID] = c
		return map[string]string{"subject": subject, "subjectKeyId": keyID}
	}
	roots := []map[string]string{{"subject": matterCertificationCASubject, "subjectKeyId": matterCertificationCAKeyID}}
	for _, c := range paas {
		roots = append(roots, id(c))
	}
	var children []map[string]string
	for _, c := range cds {
		children = append(children, id(c))
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/dcl/pki/root-certificates", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"approvedRootCertificates": map[string]any{"schemaVersion": 0, "certs": roots}})
	})
	mux.HandleFunc("/dcl/pki/child-certificates/"+matterCertificationCASubject+"/"+matterCertificationCAKeyID, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"childCertificates": map[string]any{"certIds": children}})
	})
	mux.HandleFunc("/dcl/pki/certificates/", func(w http.ResponseWriter, r *http.Request) {
		c, ok := byPath[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		p := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
		_ = json.NewEncoder(w).Encode(map[string]any{"approvedCertificates": map[string]any{"certs": []map[string]string{{"pemCert": string(p)}}}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestClientReadsPAAsAndCDSigningCertificates(t *testing.T) {
	paas := []*x509.Certificate{newRoot(t, "PAA One", 1), newRoot(t, "PAA Two", 2)}
	cds := []*x509.Certificate{newRoot(t, "CD Signing Key", 3)}
	client := NewClient(fakeLedger(t, paas, cds).URL)

	got, err := client.PAAs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !got[0].Equal(paas[0]) || !got[1].Equal(paas[1]) {
		t.Fatalf("PAAs() = %d certificates, want the 2 PAAs without the Matter Certification and Testing CA", len(got))
	}
	gotCDs, err := client.CDSigningCertificates(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(gotCDs) != 1 || !gotCDs[0].Equal(cds[0]) {
		t.Fatalf("CDSigningCertificates() = %d certificates, want 1", len(gotCDs))
	}
}

func TestClientReportsHTTPErrors(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	if _, err := NewClient(srv.URL).PAAs(context.Background()); err == nil {
		t.Fatal("PAAs() error = nil, want the HTTP error")
	}
}

func TestWriteCertificatesReplacesTheDERFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "stale.der"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	certs := []*x509.Certificate{newRoot(t, "A", 1), newRoot(t, "B", 2)}
	if err := WriteCertificates(dir, append(certs, certs[0])); err != nil {
		t.Fatal(err)
	}
	ders, _ := filepath.Glob(filepath.Join(dir, "*.der"))
	if len(ders) != 2 {
		t.Fatalf("%d .der files, want 2", len(ders))
	}
	if _, err := os.Stat(filepath.Join(dir, "README.md")); err != nil {
		t.Fatal("WriteCertificates() removed a file which is not a certificate")
	}
	b, err := os.ReadFile(filepath.Join(dir, FileName(certs[1])))
	if err != nil {
		t.Fatal(err)
	}
	if c, err := x509.ParseCertificate(b); err != nil || !c.Equal(certs[1]) {
		t.Fatal("the written certificate does not read back")
	}
}
