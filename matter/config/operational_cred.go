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

package config

// OperationalCredentialsConfigHelper defines the interface for map and string representations
// of operational credentials configuration.
type OperationalCredentialsConfigHelper interface {
	// Map returns a map representation of the OperationalCredentialsConfig.
	Map() map[string]any
	// String returns a human-readable string representation of the OperationalCredentialsConfig.
	String() string
}

// OperationalCredentialsConfig holds the credentials required for operational commissioning.
// Matter 1.2 Core Spec 11.17.6 "Commands" defines the AddNOC command fields.
// Newer Matter revisions keep the same AddNOC field shape under the Node Operational Credentials cluster.
type OperationalCredentialsConfig interface {
	OperationalCredentialsConfigHelper
	// RootCertificate returns the Root CA Certificate (RCAC) as a DER-encoded octet string.
	// This value is commissioner-provided input for AddTrustedRootCertificate, not a spec-defined default.
	RootCertificate() ([]byte, bool)
	// NOC returns the Node Operational Certificate as a DER-encoded octet string.
	// This value is commissioner-provided input for AddNOC, not a spec-defined default.
	NOC() ([]byte, bool)
	// ICAC returns the Intermediate CA Certificate as a DER-encoded octet string.
	// ICAC is optional; returns false if not set.
	// Matter 1.2 Core Spec 4.13.2 "Certificate Authenticated Session Establishment (CASE)"
	// treats ICAC as present only when applicable ("ICAC ... if present").
	ICAC() ([]byte, bool)
	// IPK returns the Identity Protection Key as an octet string.
	// This value is commissioner-provided input for AddNOC, not a spec-defined default.
	IPK() ([]byte, bool)
	// CASEAdminNodeID returns the Node ID of the CASE admin subject.
	// AddNOC uses this as the CaseAdminSubject field, which must identify the actual CASE administrator subject.
	CASEAdminNodeID() (uint64, bool)
	// AdminVendorID returns the Vendor ID of the commissioner.
	// Matter 1.2 Core Spec 6.4.6 "Node Operational Credentials Procedure", step 9,
	// requires AddNOC.AdminVendorId to be the commissioner's manufacturer Vendor ID in DCL.
	AdminVendorID() (uint16, bool)
}
