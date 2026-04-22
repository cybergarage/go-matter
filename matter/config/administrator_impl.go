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

import "github.com/cybergarage/go-matter/matter/encoding/json"

// AdministratorConfigOption defines a functional option for configuring AdministratorConfig.
type AdministratorConfigOption func(*administratorConfig)

// WithAdministratorNodeID sets the administrator operational node ID.
func WithAdministratorNodeID(nodeID uint64) AdministratorConfigOption {
	return func(c *administratorConfig) {
		c.nodeID = &nodeID
	}
}

// WithAdministratorFabricID sets the target fabric identifier.
func WithAdministratorFabricID(fabricID uint64) AdministratorConfigOption {
	return func(c *administratorConfig) {
		c.fabricID = &fabricID
	}
}

// WithAdministratorRootCertificate sets the trust anchor used for CASE peer validation.
func WithAdministratorRootCertificate(cert []byte) AdministratorConfigOption {
	return func(c *administratorConfig) {
		c.rootCertificate = cert
	}
}

// WithAdministratorNOC sets the administrator node operational certificate.
func WithAdministratorNOC(noc []byte) AdministratorConfigOption {
	return func(c *administratorConfig) {
		c.noc = noc
	}
}

// WithAdministratorICAC sets the administrator intermediate certificate.
func WithAdministratorICAC(icac []byte) AdministratorConfigOption {
	return func(c *administratorConfig) {
		c.icac = icac
	}
}

// WithAdministratorPrivateKey sets the signer material for CASE Sigma3.
func WithAdministratorPrivateKey(key []byte) AdministratorConfigOption {
	return func(c *administratorConfig) {
		c.privateKey = key
	}
}

type administratorConfig struct {
	nodeID          *uint64
	fabricID        *uint64
	rootCertificate []byte
	noc             []byte
	icac            []byte
	privateKey      []byte
}

func newAdministratorConfig(opts ...AdministratorConfigOption) *administratorConfig {
	c := &administratorConfig{
		nodeID:          nil,
		fabricID:        nil,
		rootCertificate: nil,
		noc:             nil,
		icac:            nil,
		privateKey:      nil,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// NewAdministratorConfig creates a new AdministratorConfig with the provided options.
func NewAdministratorConfig(opts ...AdministratorConfigOption) AdministratorConfig {
	return newAdministratorConfig(opts...)
}

func (c *administratorConfig) NodeID() (uint64, bool) {
	if c.nodeID == nil {
		return 0, false
	}
	return *c.nodeID, true
}

func (c *administratorConfig) FabricID() (uint64, bool) {
	if c.fabricID == nil {
		return 0, false
	}
	return *c.fabricID, true
}

func (c *administratorConfig) RootCertificate() ([]byte, bool) {
	if c.rootCertificate == nil {
		return nil, false
	}
	return c.rootCertificate, true
}

func (c *administratorConfig) NOC() ([]byte, bool) {
	if c.noc == nil {
		return nil, false
	}
	return c.noc, true
}

func (c *administratorConfig) ICAC() ([]byte, bool) {
	if c.icac == nil {
		return nil, false
	}
	return c.icac, true
}

func (c *administratorConfig) PrivateKey() ([]byte, bool) {
	if c.privateKey == nil {
		return nil, false
	}
	return c.privateKey, true
}

func (c *administratorConfig) Map() map[string]any {
	m := make(map[string]any)
	if c.nodeID != nil {
		m["nodeID"] = *c.nodeID
	}
	if c.fabricID != nil {
		m["fabricID"] = *c.fabricID
	}
	if c.rootCertificate != nil {
		m["rootCertificate"] = c.rootCertificate
	}
	if c.noc != nil {
		m["noc"] = c.noc
	}
	if c.icac != nil {
		m["icac"] = c.icac
	}
	if c.privateKey != nil {
		m["privateKey"] = c.privateKey
	}
	return m
}

func (c *administratorConfig) String() string {
	return json.MustMarshal(c.Map())
}
