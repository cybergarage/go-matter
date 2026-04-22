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
	"strings"
	"testing"

	"github.com/cybergarage/go-matter/matter/config"
)

func TestCommissionOperationalCredentialsNilConfig(t *testing.T) {
	err := commissionOperationalCredentials(nil, nil)
	if err == nil {
		t.Fatal("commissionOperationalCredentials(nil, nil) error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "operational credentials config is required") {
		t.Fatalf("commissionOperationalCredentials(nil, nil) error = %q, want missing config error", err)
	}
}

func TestCommissionOperationalCredentialsMissingRequiredInputs(t *testing.T) {
	tests := []struct {
		name    string
		cfg     config.OperationalCredentialsConfig
		wantErr string
	}{
		{
			name: "missing root certificate",
			cfg: config.NewOperationalCredentialConfig(
				config.WithNOC([]byte{0x01}),
				config.WithIPK([]byte{0x02}),
				config.WithCASEAdminNodeID(1),
				config.WithAdminVendorID(1),
			),
			wantErr: "missing root certificate",
		},
		{
			name: "missing noc",
			cfg: config.NewOperationalCredentialConfig(
				config.WithRootCertificate([]byte{0x01}),
				config.WithIPK([]byte{0x02}),
				config.WithCASEAdminNodeID(1),
				config.WithAdminVendorID(1),
			),
			wantErr: "missing NOC",
		},
		{
			name: "missing ipk",
			cfg: config.NewOperationalCredentialConfig(
				config.WithRootCertificate([]byte{0x01}),
				config.WithNOC([]byte{0x02}),
				config.WithCASEAdminNodeID(1),
				config.WithAdminVendorID(1),
			),
			wantErr: "missing IPK",
		},
		{
			name: "missing case admin node id",
			cfg: config.NewOperationalCredentialConfig(
				config.WithRootCertificate([]byte{0x01}),
				config.WithNOC([]byte{0x02}),
				config.WithIPK([]byte{0x03}),
				config.WithAdminVendorID(1),
			),
			wantErr: "missing CASE admin node ID",
		},
		{
			name: "missing admin vendor id",
			cfg: config.NewOperationalCredentialConfig(
				config.WithRootCertificate([]byte{0x01}),
				config.WithNOC([]byte{0x02}),
				config.WithIPK([]byte{0x03}),
				config.WithCASEAdminNodeID(1),
			),
			wantErr: "missing admin vendor ID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := commissionOperationalCredentials(nil, tt.cfg)
			if err == nil {
				t.Fatalf("commissionOperationalCredentials(nil, cfg) error = nil, want %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("commissionOperationalCredentials(nil, cfg) error = %q, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestCommissionNetworkNilConfig(t *testing.T) {
	if err := commissionNetwork(nil, nil, false); err != nil {
		t.Fatalf("commissionNetwork(nil, nil, false) error = %v, want nil", err)
	}

	err := commissionNetwork(nil, nil, true)
	if err == nil {
		t.Fatal("commissionNetwork(nil, nil, true) error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "Wi-Fi network config is required") {
		t.Fatalf("commissionNetwork(nil, nil, true) error = %q, want missing config error", err)
	}
}

func TestCommissionNetworkMissingRequiredInputs(t *testing.T) {
	tests := []struct {
		name    string
		cfg     config.WiFiNetworkConfig
		wantErr string
	}{
		{
			name: "missing ssid",
			cfg: config.NewWiFiNetworkConfig(
				config.WithCredentials([]byte("passphrase")),
			),
			wantErr: "missing SSID",
		},
		{
			name: "missing credentials",
			cfg: config.NewWiFiNetworkConfig(
				config.WithSSID([]byte("ssid")),
			),
			wantErr: "missing credentials",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := commissionNetwork(nil, tt.cfg, true)
			if err == nil {
				t.Fatalf("commissionNetwork(nil, cfg, true) error = nil, want %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("commissionNetwork(nil, cfg, true) error = %q, want substring %q", err, tt.wantErr)
			}
		})
	}
}
