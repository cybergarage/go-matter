// Copyright (C) 2026 The go-matter Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mockdevice

import "crypto/ecdsa"

// fabricState holds everything this mock device learns/generates while
// being commissioned: its attestation identity, the operational keypair it
// generates on CSRRequest, and the fabric material (root cert, its own NOC,
// IPK) it receives via AddTrustedRootCertificate/AddNOC. CASE (once
// commissioning reaches it) reads this same state to match Sigma1's
// DestinationID and to build/verify Sigma2/Sigma3.
type fabricState struct {
	attestation attestationIdentity

	// nocKey is generated fresh when CSRRequest is handled — this mock
	// device's own operational (NOC) private key, distinct from its DAC key.
	nocKey *ecdsa.PrivateKey

	rootCertDER []byte // from AddTrustedRootCertificate, DER (converted from the received Matter-TLV)
	nocDER      []byte // from AddNOC, DER (converted from the received Matter-TLV)
	icacDER     []byte // from AddNOC, DER, nil if none was sent

	rawIPK           []byte // from AddNOC, the raw 16-byte epoch key as received
	caseAdminSubject uint64 // from AddNOC
	adminVendorID    uint16 // from AddNOC

	nodeID   uint64 // parsed from nocDER's Subject NodeID RDN after AddNOC
	fabricID uint64 // parsed from nocDER's Subject FabricID RDN after AddNOC
}

func newFabricState(attestation attestationIdentity) *fabricState {
	return &fabricState{attestation: attestation}
}
