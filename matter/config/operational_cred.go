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
// 11.18.6.8. AddNOC Command.
type OperationalCredentialsConfig interface {
	OperationalCredentialsConfigHelper
	// RootCertificate returns the Root CA Certificate (RCAC) as a DER-encoded octet string.
	RootCertificate() ([]byte, bool)
	// NOC returns the Node Operational Certificate as a DER-encoded octet string.
	NOC() ([]byte, bool)
	// ICAC returns the Intermediate CA Certificate as a DER-encoded octet string.
	// ICAC is optional; returns false if not set.
	ICAC() ([]byte, bool)
	// IPK returns the Identity Protection Key as an octet string.
	IPK() ([]byte, bool)
	// CASEAdminNodeID returns the Node ID of the CASE admin subject.
	CASEAdminNodeID() (uint64, bool)
	// AdminVendorID returns the Vendor ID of the commissioner.
	AdminVendorID() (uint16, bool)
}
