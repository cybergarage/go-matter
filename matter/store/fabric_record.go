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

package store

import "time"

// FabricRecord is the commissioner-wide identity shared by every device
// commissioned onto the same fabric: the administrator's own operational
// identity (config.AdministratorConfig) plus the fabric-wide fields of
// config.OperationalCredentialsConfig actually consumed during
// commissioning (IPK, AdminVendorID; CASEAdminNodeID is not duplicated
// here since it must equal AdminNodeID). It deliberately excludes
// OperationalCredentialsConfig's RootCertificate/NOC/ICAC fields, which
// commissioning_impl.go never reads (the RCAC/NOC actually sent to a
// device always come from the administrator's own CertificateAuthority).
type FabricRecord struct {
	FabricID        uint64    `json:"fabricId"`
	AdminNodeID     uint64    `json:"adminNodeId"`
	AdminVendorID   uint16    `json:"adminVendorId"`
	RootCertificate []byte    `json:"rootCertificate"`
	RootPrivateKey  []byte    `json:"rootPrivateKey"`
	NOC             []byte    `json:"noc"`
	ICAC            []byte    `json:"icac,omitempty"`
	PrivateKey      []byte    `json:"privateKey"`
	IPK             []byte    `json:"ipk"`
	UpdatedAt       time.Time `json:"updatedAt"`
}
