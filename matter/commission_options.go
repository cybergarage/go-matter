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

package matter

import (
	"github.com/cybergarage/go-matter/matter/config"
)

// CommissionOption configures one commissioning. It is made by the
// WithCommission… functions and WithCommissioningProgress; when an option
// is given more than once, the last one wins.
type CommissionOption interface {
	commissionOption()
}

type nodeIDOption NodeID

type wifiNetworkOption struct{ cfg config.WiFiNetworkConfig }

type administratorOption struct{ cfg config.AdministratorConfig }

type operationalCredentialsOption struct {
	cfg config.OperationalCredentialsConfig
}

type attestationVerifierOption struct{ v AttestationVerifier }

type progressOption CommissioningProgressFunc

func (nodeIDOption) commissionOption()                 {}
func (wifiNetworkOption) commissionOption()            {}
func (administratorOption) commissionOption()          {}
func (operationalCredentialsOption) commissionOption() {}
func (attestationVerifierOption) commissionOption()    {}
func (progressOption) commissionOption()               {}

// WithCommissionNodeID requests the operational node ID the device is to
// get. Zero, the default, has the commissioner pick a random one which no
// commissioned node of its fabric has. 2.5.5. Operational Node ID.
func WithCommissionNodeID(id NodeID) CommissionOption {
	return nodeIDOption(id)
}

// WithCommissionWiFiNetwork gives the Wi-Fi network a device found over
// BLE is to join. Commissioning over BLE without it fails with
// ErrWiFiNetworkRequired.
func WithCommissionWiFiNetwork(cfg config.WiFiNetworkConfig) CommissionOption {
	return wifiNetworkOption{cfg: cfg}
}

// WithCommissionAdministratorConfig commissions the device into the fabric
// of cfg instead of the commissioner's.
func WithCommissionAdministratorConfig(cfg config.AdministratorConfig) CommissionOption {
	return administratorOption{cfg: cfg}
}

// WithCommissionOperationalCredentialsConfig gives the operational
// credentials, such as the IPK and the CASE admin subject, instead of the
// commissioner's.
func WithCommissionOperationalCredentialsConfig(cfg config.OperationalCredentialsConfig) CommissionOption {
	return operationalCredentialsOption{cfg: cfg}
}

// WithCommissionAttestationVerifier verifies the device attestation with v
// instead of the commissioner's verifier.
func WithCommissionAttestationVerifier(v AttestationVerifier) CommissionOption {
	return attestationVerifierOption{v: v}
}
