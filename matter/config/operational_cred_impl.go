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

import (
	"github.com/cybergarage/go-matter/matter/encoding/json"
)

// OperationalCredentialsConfigOption defines a functional option for configuring OperationalCredentialsConfig.
type OperationalCredentialsConfigOption func(*operationalCredentialsConfig)

// WithRootCertificate sets the Root CA Certificate (RCAC).
func WithRootCertificate(cert []byte) OperationalCredentialsConfigOption {
	return func(c *operationalCredentialsConfig) {
		c.rootCertificate = cert
	}
}

// WithNOC sets the Node Operational Certificate.
func WithNOC(noc []byte) OperationalCredentialsConfigOption {
	return func(c *operationalCredentialsConfig) {
		c.noc = noc
	}
}

// WithICAC sets the Intermediate CA Certificate (optional).
func WithICAC(icac []byte) OperationalCredentialsConfigOption {
	return func(c *operationalCredentialsConfig) {
		c.icac = icac
	}
}

// WithIPK sets the Identity Protection Key.
func WithIPK(ipk []byte) OperationalCredentialsConfigOption {
	return func(c *operationalCredentialsConfig) {
		c.ipk = ipk
	}
}

// WithCASEAdminNodeID sets the Node ID of the CASE admin subject.
func WithCASEAdminNodeID(nodeID uint64) OperationalCredentialsConfigOption {
	return func(c *operationalCredentialsConfig) {
		c.caseAdminNodeID = &nodeID
	}
}

// WithAdminVendorID sets the Vendor ID of the commissioner.
func WithAdminVendorID(vendorID uint16) OperationalCredentialsConfigOption {
	return func(c *operationalCredentialsConfig) {
		c.adminVendorID = &vendorID
	}
}

type operationalCredentialsConfig struct {
	rootCertificate []byte
	noc             []byte
	icac            []byte
	ipk             []byte
	caseAdminNodeID *uint64
	adminVendorID   *uint16
}

func newOperationalCredentialsConfig(opts ...OperationalCredentialsConfigOption) *operationalCredentialsConfig {
	c := &operationalCredentialsConfig{}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// NewOperationalCredentialConfig creates a new OperationalCredentialsConfig with the provided options.
func NewOperationalCredentialConfig(opts ...OperationalCredentialsConfigOption) OperationalCredentialsConfig {
	return newOperationalCredentialsConfig(opts...)
}

func (c *operationalCredentialsConfig) RootCertificate() ([]byte, bool) {
	if c.rootCertificate == nil {
		return nil, false
	}
	return c.rootCertificate, true
}

func (c *operationalCredentialsConfig) NOC() ([]byte, bool) {
	if c.noc == nil {
		return nil, false
	}
	return c.noc, true
}

func (c *operationalCredentialsConfig) ICAC() ([]byte, bool) {
	if c.icac == nil {
		return nil, false
	}
	return c.icac, true
}

func (c *operationalCredentialsConfig) IPK() ([]byte, bool) {
	if c.ipk == nil {
		return nil, false
	}
	return c.ipk, true
}

func (c *operationalCredentialsConfig) CASEAdminNodeID() (uint64, bool) {
	if c.caseAdminNodeID == nil {
		return 0, false
	}
	return *c.caseAdminNodeID, true
}

func (c *operationalCredentialsConfig) AdminVendorID() (uint16, bool) {
	if c.adminVendorID == nil {
		return 0, false
	}
	return *c.adminVendorID, true
}

func (c *operationalCredentialsConfig) Map() map[string]any {
	m := make(map[string]any)
	if c.rootCertificate != nil {
		m["rootCertificate"] = c.rootCertificate
	}
	if c.noc != nil {
		m["noc"] = c.noc
	}
	if c.icac != nil {
		m["icac"] = c.icac
	}
	if c.ipk != nil {
		m["ipk"] = c.ipk
	}
	if c.caseAdminNodeID != nil {
		m["caseAdminNodeID"] = *c.caseAdminNodeID
	}
	if c.adminVendorID != nil {
		m["adminVendorID"] = *c.adminVendorID
	}
	return m
}

func (c *operationalCredentialsConfig) String() string {
	return json.MustMarshal(c.Map())
}
