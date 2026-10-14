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

package caseprotocol

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"testing"
)

// identityTestCertificate returns a certificate whose subject carries the
// Matter node ID and fabric ID attributes (6.5.6.1. Matter DN attributes).
func identityTestCertificate(nodeID, fabricID uint64) *x509.Certificate {
	return &x509.Certificate{
		Subject: pkix.Name{
			Names: []pkix.AttributeTypeAndValue{
				{Type: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37244, 1, 1}, Value: fmt.Sprintf("%016X", nodeID)},
				{Type: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37244, 1, 5}, Value: fmt.Sprintf("%016X", fabricID)},
			},
		},
	}
}

func TestVerifyResponderIdentity(t *testing.T) {
	const (
		peerNodeID = uint64(0x00000000DEADBEEF)
		fabricID   = uint64(0x0000000000000A0B)
	)
	tests := []struct {
		name    string
		noc     *x509.Certificate
		wantErr bool
	}{
		{name: "expected node and fabric", noc: identityTestCertificate(peerNodeID, fabricID), wantErr: false},
		{name: "another node of the fabric", noc: identityTestCertificate(peerNodeID+1, fabricID), wantErr: true},
		{name: "another fabric", noc: identityTestCertificate(peerNodeID, fabricID+1), wantErr: true},
		{name: "no identity", noc: &x509.Certificate{}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifyResponderIdentity(tt.noc, peerNodeID, fabricID)
			if !tt.wantErr {
				if err != nil {
					t.Fatalf("verifyResponderIdentity() error = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, ErrUnexpectedResponder) {
				t.Fatalf("verifyResponderIdentity() error = %v, want ErrUnexpectedResponder", err)
			}
		})
	}
}
