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

// AdministratorConfigHelper defines the interface for map and string representations
// of administrator credentials used for CASE finalization.
type AdministratorConfigHelper interface {
	// Map returns a map representation of the AdministratorConfig.
	Map() map[string]any
	// String returns a human-readable string representation of the AdministratorConfig.
	String() string
}

// AdministratorConfig holds the commissioner / administrator credentials required
// to finalize commissioning over CASE on the operational network.
type AdministratorConfig interface {
	AdministratorConfigHelper
	// NodeID returns the administrator's operational node ID used as the CASE initiator identity.
	NodeID() (uint64, bool)
	// FabricID returns the target fabric identifier for the CASE session.
	FabricID() (uint64, bool)
	// RootCertificate returns the trust anchor used to validate the commissionee's CASE chain.
	RootCertificate() ([]byte, bool)
	// NOC returns the administrator node operational certificate used for CASE.
	NOC() ([]byte, bool)
	// ICAC returns the optional intermediate certificate used for CASE.
	ICAC() ([]byte, bool)
	// PrivateKey returns signer material for CASE Sigma3.
	PrivateKey() ([]byte, bool)
}
