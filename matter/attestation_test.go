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
	"bytes"
	"errors"
	"testing"

	"github.com/cybergarage/go-matter/matter/credentials"
	"github.com/cybergarage/go-matter/matter/credentials/testcreds"
)

// testcredsAttestation returns the AttestationInfo of a device attesting
// with the Matter SDK's test credentials, as go-matter's device does.
func testcredsAttestation(t *testing.T) credentials.AttestationInfo {
	t.Helper()
	provider, err := testcreds.AttestationProvider()
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{0x24}, 32)
	challenge := bytes.Repeat([]byte{0x5A}, 16)
	elements, err := credentials.BuildAttestationElements(provider.CertificationDeclaration(), nonce, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := credentials.SignWithChallenge(provider.SignWithDAC, elements, challenge)
	if err != nil {
		t.Fatal(err)
	}
	return credentials.AttestationInfo{
		DAC:                  provider.DAC(),
		PAI:                  provider.PAI(),
		AttestationElements:  elements,
		AttestationSignature: sig,
		AttestationChallenge: challenge,
		AttestationNonce:     nonce,
		VendorID:             testcreds.VendorID,
		ProductID:            testcreds.ProductID,
		HasBasicInformation:  true,
	}
}

func TestDefaultAttestationVerifierAcceptsTestCredentials(t *testing.T) {
	if err := DefaultAttestationVerifier().VerifyAttestation(testcredsAttestation(t)); err != nil {
		t.Fatalf("VerifyAttestation() error = %v, want nil", err)
	}
}

func TestProductionAttestationTrustStoreHoldsTheCSACDSigningKeys(t *testing.T) {
	store := ProductionAttestationTrustStore()
	if got := len(store.CDSigningCertificates()); got != 5 {
		t.Fatalf("CDSigningCertificates() = %d certificates, want the 5 keys of the CSA", got)
	}
	for _, c := range store.CDSigningCertificates() {
		if c.Subject.Organization[0] != "CSA" {
			t.Errorf("CD signing certificate %q is not the CSA's", c.Subject.CommonName)
		}
	}
}

func TestProductionAttestationTrustStoreHoldsTheDCLPAAs(t *testing.T) {
	if got := len(ProductionAttestationTrustStore().PAAs()); got < 50 {
		t.Fatalf("PAAs() = %d certificates, want the DCL's", got)
	}
}

func TestProductionAttestationVerifierRejectsTestCredentials(t *testing.T) {
	err := NewAttestationVerifier(AttestationProduction).VerifyAttestation(testcredsAttestation(t))
	var ae *credentials.AttestationError
	if !errors.As(err, &ae) || ae.Failure != credentials.AttestationFailureTestVendorID {
		t.Fatalf("VerifyAttestation() error = %v, want a test vendor ID failure", err)
	}
}

func TestCommissionerUsesTheAttestationModeByDefault(t *testing.T) {
	tests := []struct {
		name    string
		opts    []CommissionerOption
		wantErr bool
	}{
		{name: "default", opts: nil, wantErr: false},
		{name: "production", opts: []CommissionerOption{WithCommissionerAttestationMode(AttestationProduction)}, wantErr: true},
		{name: "none", opts: []CommissionerOption{WithCommissionerAttestationMode(AttestationNone)}, wantErr: false},
		{
			name: "verifier overrides the mode",
			opts: []CommissionerOption{
				WithCommissionerAttestationMode(AttestationProduction),
				WithCommissionerAttestationVerifier(DefaultAttestationVerifier()),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmr, ok := NewCommissioner(tt.opts...).(*commissioner)
			if !ok {
				t.Fatal("NewCommissioner() is not a *commissioner")
			}
			var verifier AttestationVerifier
			for _, opt := range cmr.commissionOptions() {
				if v, ok := opt.(AttestationVerifier); ok {
					verifier = v
				}
			}
			if verifier == nil {
				t.Fatal("commissionOptions() carries no AttestationVerifier")
			}
			err := verifier.VerifyAttestation(testcredsAttestation(t))
			if (err != nil) != tt.wantErr {
				t.Fatalf("VerifyAttestation() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
