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
	// vendor IDs.
	AttestationProduction = credentials.AttestationProduction
	// AttestationNone does not verify the chain of trust.
	AttestationNone = credentials.AttestationNone
)

// AttestationTrustStore holds the PAAs and the Certification Declaration
// signing certificates a Commissioner trusts.
type AttestationTrustStore = credentials.AttestationTrustStore

// AttestationVerifier decides whether a device's attestation is trusted.
type AttestationVerifier = credentials.AttestationVerifier

// DevelopmentAttestationTrustStore returns the anchors trusted in
// AttestationDevelopment besides the production ones: the test PAA and the
// Certification Declaration signing certificate of the Matter SDK, which
// its example devices and go-matter's testcreds attest with.
func DevelopmentAttestationTrustStore() AttestationTrustStore {
	return mustParseAttestationTrustStore(testcreds.PAA(), testcreds.CDSigningCertificate())
}

// ProductionAttestationTrustStore returns the production anchors go-matter
// bundles. It is empty until the production PAAs of the Distributed
// Compliance Ledger are bundled; add them with
// WithCommissionerAttestationTrustStore meanwhile.
func ProductionAttestationTrustStore() AttestationTrustStore {
	return credentials.NewAttestationTrustStore(nil, nil)
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
	return credentials.NewAttestationVerifier(mode, credentials.MergeAttestationTrustStores(stores...))
}

// DefaultAttestationVerifier returns the verifier of a Commissioner which
// was not given another: AttestationDevelopment with the bundled anchors.
func DefaultAttestationVerifier() AttestationVerifier {
	return NewAttestationVerifier(AttestationDevelopment)
}

func mustParseAttestationTrustStore(certs ...[]byte) AttestationTrustStore {
	store, err := credentials.ParseAttestationTrustStore(certs...)
	if err != nil {
		// The bundled certificates are fixed: a failure is a build error.
		log.Errorf("matter: bundled attestation trust store: %v", err)
		return credentials.NewAttestationTrustStore([]*x509.Certificate{}, []*x509.Certificate{})
	}
	return store
}
