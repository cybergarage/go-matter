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

// Package caseprotocol provides CASE (Certificate Authenticated Session Establishment)
// client primitives used to finalize commissioning over the operational network.
package caseprotocol

import (
	"context"
	"errors"
	"fmt"

	"github.com/cybergarage/go-matter/matter/config"
	"github.com/cybergarage/go-matter/matter/io"
	"github.com/cybergarage/go-matter/matter/protocol/session"
)

// Transport is the underlying byte-oriented transport used for CASE.
type Transport = io.Transport

// ErrNotImplemented is returned while CASE Sigma exchange support is not yet implemented.
var ErrNotImplemented = errors.New("case: not yet implemented")

// Initiator represents a CASE client.
type Initiator struct {
	t   Transport
	cfg config.AdministratorConfig
}

// NewInitiator creates a new CASE initiator.
func NewInitiator(t Transport, cfg config.AdministratorConfig) *Initiator {
	return &Initiator{
		t:   t,
		cfg: cfg,
	}
}

// EstablishSession validates CASE prerequisites and will eventually establish a CASE session.
func (i *Initiator) EstablishSession(_ context.Context) (session.SessionKeys, error) {
	if i.t == nil {
		return nil, fmt.Errorf("case: transport is required")
	}
	if i.cfg == nil {
		return nil, fmt.Errorf("case: administrator config is required")
	}
	if _, err := loadAdministratorInputs(i.cfg); err != nil {
		return nil, err
	}
	return nil, ErrNotImplemented
}

type administratorInputs struct {
	nodeID          uint64
	fabricID        uint64
	rootCertificate []byte
	noc             []byte
	icac            []byte
	privateKey      []byte
}

func loadAdministratorInputs(cfg config.AdministratorConfig) (administratorInputs, error) {
	nodeID, _ := cfg.NodeID()
	fabricID, _ := cfg.FabricID()
	rootCert, _ := cfg.RootCertificate()
	noc, _ := cfg.NOC()
	icac, _ := cfg.ICAC()
	privateKey, _ := cfg.PrivateKey()

	if nodeID == 0 {
		return administratorInputs{}, fmt.Errorf("case: administrator config missing node ID")
	}
	if fabricID == 0 {
		return administratorInputs{}, fmt.Errorf("case: administrator config missing fabric ID")
	}
	if len(rootCert) == 0 {
		return administratorInputs{}, fmt.Errorf("case: administrator config missing root certificate")
	}
	if len(noc) == 0 {
		return administratorInputs{}, fmt.Errorf("case: administrator config missing NOC")
	}
	if len(privateKey) == 0 {
		return administratorInputs{}, fmt.Errorf("case: administrator config missing private key")
	}

	return administratorInputs{
		nodeID:          nodeID,
		fabricID:        fabricID,
		rootCertificate: rootCert,
		noc:             noc,
		icac:            icac,
		privateKey:      privateKey,
	}, nil
}
