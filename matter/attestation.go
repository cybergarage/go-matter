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

package matter

import (
	"crypto/x509"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter/credentials"
	"github.com/cybergarage/go-matter/matter/credentials/production"
	"github.com/cybergarage/go-matter/matter/credentials/testcreds"
)

// AttestationMode selects how strictly a Commissioner verifies device
// attestation; see credentials.AttestationMode.
type AttestationMode = credentials.AttestationMode

const (
	// AttestationDevelopment, the default, trusts the production anchors,
	// the test anchors of the Matter SDK and any added with
	// WithCommissionerAttestationTrustStore.
	AttestationDevelopment = credentials.AttestationDevelopment
	// AttestationProduction trusts the production anchors and those added
	// with WithCommissionerAttestationTrustStore only, and rejects test
	// vendor IDs and the test anchors of the Matter SDK.
	AttestationProduction = credentials.AttestationProduction
	// AttestationNone does not verify the chain of trust.
	AttestationNone = credentials.AttestationNone
)

// AttestationTrustStore holds the PAAs and the Certification Declaration
// signing certificates a Commissioner trusts.
type AttestationTrustStore = credentials.AttestationTrustStore

// AttestationVerifier decides whether a device's attestation is trusted.
type AttestationVerifier = credentials.AttestationVerifier

// DevelopmentAttestationTrustStore returns the test anchors of the Matter
// SDK, whose private keys are public: its test PAA, which go-matter's
// testcreds chain to, and its test Certification Declaration signing key.
// AttestationDevelopment trusts them besides the production anchors;
// AttestationProduction rejects them.
func DevelopmentAttestationTrustStore() AttestationTrustStore {
	return mustParseAttestationTrustStore(
		[][]byte{testcreds.PAA()},
		[][]byte{testcreds.TestCDSigningCertificate()},
	)
}

// ProductionAttestationTrustStore returns the production anchors go-matter
// bundles: a snapshot of the approved PAAs and the Certification
// Declaration signing keys of the Distributed Compliance Ledger. A PAA
// approved after the snapshot can be added with
// WithCommissionerAttestationTrustStore, or read from the ledger with
// credentials/dcl.
func ProductionAttestationTrustStore() AttestationTrustStore {
	return mustParseAttestationTrustStore(production.PAAs(), production.CDSigningCertificates())
}

// NewAttestationVerifier returns the verifier a Commissioner uses for the
// mode: it trusts the mode's bundled anchors and those of the extra
// stores.
func NewAttestationVerifier(mode AttestationMode, extra ...AttestationTrustStore) AttestationVerifier {
	stores := []AttestationTrustStore{ProductionAttestationTrustStore()}
	if mode == AttestationDevelopment {
		stores = append(stores, DevelopmentAttestationTrustStore())
	}
	stores = append(stores, extra...)
	var opts []credentials.AttestationVerifierOption
	if mode == AttestationProduction {
		opts = append(opts, credentials.WithAttestationRejectedAnchors(DevelopmentAttestationTrustStore()))
	}
	return credentials.NewAttestationVerifier(mode, credentials.MergeAttestationTrustStores(stores...), opts...)
}

// DefaultAttestationVerifier returns the verifier of a Commissioner which
// was not given another: AttestationDevelopment with the bundled anchors.
func DefaultAttestationVerifier() AttestationVerifier {
	return NewAttestationVerifier(AttestationDevelopment)
}

// mustParseAttestationTrustStore parses bundled certificates one by one, so
// that a certificate which does not parse drops itself only.
func mustParseAttestationTrustStore(paas, cdSigners [][]byte) AttestationTrustStore {
	return credentials.NewAttestationTrustStore(parseBundledCertificates(paas), parseBundledCertificates(cdSigners))
}

func parseBundledCertificates(list [][]byte) []*x509.Certificate {
	certs := make([]*x509.Certificate, 0, len(list))
	for _, b := range list {
		cert, err := x509.ParseCertificate(b)
		if err != nil {
			log.Errorf("matter: bundled attestation trust anchor: %v", err)
			continue
		}
		certs = append(certs, cert)
	}
	return certs
}
