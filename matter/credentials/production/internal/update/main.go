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

// Command update refreshes the production trust anchors bundled in
// matter/credentials/production/certs: the PAAs in certs/paa and the
// Certification Declaration signing certificates in certs/cd.
//
//	go run ./matter/credentials/production/internal/update
//
// reads them from the production Distributed Compliance Ledger.
//
//	go run ./matter/credentials/production/internal/update -paa-dir DIR -cd-dir DIR
//
// takes them from directories of .der and .pem files instead, such as the
// DCL mirror of the Matter SDK in credentials/production.
package main

import (
	"context"
	"crypto/x509"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/cybergarage/go-matter/matter/credentials"
	"github.com/cybergarage/go-matter/matter/credentials/dcl"
)

func main() {
	out := flag.String("out", "matter/credentials/production/certs", "the certs directory to update")
	url := flag.String("dcl", dcl.MainNetURL, "the REST endpoint of the ledger")
	paaDir := flag.String("paa-dir", "", "read the PAAs from this directory instead of the ledger")
	cdDir := flag.String("cd-dir", "", "read the CD signing certificates from this directory instead of the ledger")
	flag.Parse()
	if err := run(*out, *url, *paaDir, *cdDir); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(out, url, paaDir, cdDir string) error {
	var paas, cds []*x509.Certificate
	date := time.Now().UTC().Format(time.DateOnly)
	source := fmt.Sprintf("Distributed Compliance Ledger, %s, fetched %s", url, date)
	if paaDir != "" || cdDir != "" {
		source = fmt.Sprintf("PAAs from %s and CD signing certificates from %s, imported %s", paaDir, cdDir, date)
		store, err := credentials.LoadAttestationTrustStore(paaDir, cdDir)
		if err != nil {
			return err
		}
		paas, cds = store.PAAs(), store.CDSigningCertificates()
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		client := dcl.NewClient(url)
		var err error
		if paas, err = client.PAAs(ctx); err != nil {
			return err
		}
		if cds, err = client.CDSigningCertificates(ctx); err != nil {
			return err
		}
	}
	// An empty set is an error rather than "nothing changed": the ledger
	// always has both, and a response whose shape changed decodes to none.
	if len(paas) == 0 || len(cds) == 0 {
		return fmt.Errorf("update: %d PAAs and %d CD signing certificates; want both", len(paas), len(cds))
	}
	if err := dcl.WriteCertificates(filepath.Join(out, "paa"), paas); err != nil {
		return err
	}
	if err := dcl.WriteCertificates(filepath.Join(out, "cd"), cds); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, "SOURCE"), []byte(source+"\n"), 0o644); err != nil {
		return fmt.Errorf("update: %w", err)
	}
	fmt.Printf("%d PAAs, %d CD signing certificates from %s\n", len(paas), len(cds), source)
	return nil
}
