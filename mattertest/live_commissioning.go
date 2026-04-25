// Copyright (C) 2024 The go-matter Authors. All rights reserved.
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

package mattertest

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/cybergarage/go-matter/matter"
	"github.com/cybergarage/go-matter/matter/config"
	"github.com/cybergarage/go-matter/matter/encoding"
)

var errLiveCommissioningDisabled = errors.New("live commissioner interop disabled")

type liveCommissioningScenario struct {
	Name        string
	PairingCode matter.OnboardingPayload
	Admin       config.AdministratorConfig
	Operational config.OperationalCredentialsConfig
	WiFi        config.WiFiNetworkConfig
}

func (s liveCommissioningScenario) Options() []matter.CommissionOption {
	opts := []matter.CommissionOption{s.Admin, s.Operational}
	if s.WiFi != nil {
		opts = append(opts, s.WiFi)
	}
	return opts
}

func loadLiveCommissioningScenarioFromEnv() (liveCommissioningScenario, error) {
	if os.Getenv("MATTER_TEST_COMMISSIONER_LIVE") != "1" {
		return liveCommissioningScenario{}, errLiveCommissioningDisabled
	}

	pairingCodeStr, err := requireEnv("MATTER_TEST_PAIRING_CODE")
	if err != nil {
		return liveCommissioningScenario{}, err
	}
	adminNodeIDStr, err := requireEnv("MATTER_TEST_ADMIN_NODE_ID")
	if err != nil {
		return liveCommissioningScenario{}, err
	}
	fabricIDStr, err := requireEnv("MATTER_TEST_FABRIC_ID")
	if err != nil {
		return liveCommissioningScenario{}, err
	}
	adminRootCert, err := envBlob("MATTER_TEST_ADMIN_ROOT_CERT")
	if err != nil {
		return liveCommissioningScenario{}, err
	}
	adminNOC, err := envBlob("MATTER_TEST_ADMIN_NOC")
	if err != nil {
		return liveCommissioningScenario{}, err
	}
	adminICAC, err := optionalEnvBlob("MATTER_TEST_ADMIN_ICAC")
	if err != nil {
		return liveCommissioningScenario{}, err
	}
	adminPrivateKey, err := envBlob("MATTER_TEST_ADMIN_PRIVATE_KEY")
	if err != nil {
		return liveCommissioningScenario{}, err
	}

	operationalRootCert, err := envBlob("MATTER_TEST_OPERATIONAL_ROOT_CERT")
	if err != nil {
		return liveCommissioningScenario{}, err
	}
	operationalNOC, err := envBlob("MATTER_TEST_OPERATIONAL_NOC")
	if err != nil {
		return liveCommissioningScenario{}, err
	}
	operationalICAC, err := optionalEnvBlob("MATTER_TEST_OPERATIONAL_ICAC")
	if err != nil {
		return liveCommissioningScenario{}, err
	}
	ipk, err := envHex("MATTER_TEST_OPERATIONAL_IPK_HEX")
	if err != nil {
		return liveCommissioningScenario{}, err
	}
	caseAdminNodeIDStr, err := requireEnv("MATTER_TEST_CASE_ADMIN_NODE_ID")
	if err != nil {
		return liveCommissioningScenario{}, err
	}
	adminVendorIDStr, err := requireEnv("MATTER_TEST_ADMIN_VENDOR_ID")
	if err != nil {
		return liveCommissioningScenario{}, err
	}

	pairingCode, err := encoding.NewPairingCodeFromString(pairingCodeStr)
	if err != nil {
		return liveCommissioningScenario{}, fmt.Errorf("MATTER_TEST_PAIRING_CODE: %w", err)
	}
	adminNodeID, err := parseUint64Env("MATTER_TEST_ADMIN_NODE_ID", adminNodeIDStr)
	if err != nil {
		return liveCommissioningScenario{}, err
	}
	fabricID, err := parseUint64Env("MATTER_TEST_FABRIC_ID", fabricIDStr)
	if err != nil {
		return liveCommissioningScenario{}, err
	}
	caseAdminNodeID, err := parseUint64Env("MATTER_TEST_CASE_ADMIN_NODE_ID", caseAdminNodeIDStr)
	if err != nil {
		return liveCommissioningScenario{}, err
	}
	adminVendorID, err := parseUint16Env("MATTER_TEST_ADMIN_VENDOR_ID", adminVendorIDStr)
	if err != nil {
		return liveCommissioningScenario{}, err
	}
	if adminNodeID != caseAdminNodeID {
		return liveCommissioningScenario{}, fmt.Errorf("administrator node ID (0x%016X) must match CASE admin node ID (0x%016X)", adminNodeID, caseAdminNodeID)
	}

	adminCfgOpts := []config.AdministratorConfigOption{
		config.WithAdministratorNodeID(adminNodeID),
		config.WithAdministratorFabricID(fabricID),
		config.WithAdministratorRootCertificate(adminRootCert),
		config.WithAdministratorNOC(adminNOC),
		config.WithAdministratorPrivateKey(adminPrivateKey),
	}
	if len(adminICAC) != 0 {
		adminCfgOpts = append(adminCfgOpts, config.WithAdministratorICAC(adminICAC))
	}
	operationalCfgOpts := []config.OperationalCredentialsConfigOption{
		config.WithRootCertificate(operationalRootCert),
		config.WithNOC(operationalNOC),
		config.WithIPK(ipk),
		config.WithCASEAdminNodeID(caseAdminNodeID),
		config.WithAdminVendorID(adminVendorID),
	}
	if len(operationalICAC) != 0 {
		operationalCfgOpts = append(operationalCfgOpts, config.WithICAC(operationalICAC))
	}

	var wifiCfg config.WiFiNetworkConfig
	wifiSSID, hasWiFiSSID := lookupTrimmedEnv("MATTER_TEST_WIFI_SSID")
	wifiPassword, hasWiFiPassword := lookupTrimmedEnv("MATTER_TEST_WIFI_PASSWORD")
	if hasWiFiSSID != hasWiFiPassword {
		return liveCommissioningScenario{}, fmt.Errorf("MATTER_TEST_WIFI_SSID and MATTER_TEST_WIFI_PASSWORD must either both be set or both be omitted")
	}
	if hasWiFiSSID {
		wifiCfg = config.NewWiFiNetworkConfig(
			config.WithSSID([]byte(wifiSSID)),
			config.WithCredentials([]byte(wifiPassword)),
		)
	}

	return liveCommissioningScenario{
		Name:        sanitizeScenarioName(os.Getenv("MATTER_TEST_SCENARIO_NAME")),
		PairingCode: pairingCode,
		Admin:       config.NewAdministratorConfig(adminCfgOpts...),
		Operational: config.NewOperationalCredentialConfig(operationalCfgOpts...),
		WiFi:        wifiCfg,
	}, nil
}

func sanitizeScenarioName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "live"
	}
	return name
}

func requireEnv(key string) (string, error) {
	v, ok := lookupTrimmedEnv(key)
	if !ok {
		return "", fmt.Errorf("%s is required", key)
	}
	return v, nil
}

func lookupTrimmedEnv(key string) (string, bool) {
	v, ok := os.LookupEnv(key)
	if !ok {
		return "", false
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return "", false
	}
	return v, true
}

func envBlob(prefix string) ([]byte, error) {
	if b, err := optionalEnvBlob(prefix); err != nil {
		return nil, err
	} else if len(b) != 0 {
		return b, nil
	}
	return nil, fmt.Errorf("%s_FILE or %s_PEM is required", prefix, prefix)
}

func optionalEnvBlob(prefix string) ([]byte, error) {
	if path, ok := lookupTrimmedEnv(prefix + "_FILE"); ok {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("%s_FILE: %w", prefix, err)
		}
		return b, nil
	}
	if pemStr, ok := lookupTrimmedEnv(prefix + "_PEM"); ok {
		return []byte(pemStr), nil
	}
	return nil, nil
}

func envHex(key string) ([]byte, error) {
	raw, ok := lookupTrimmedEnv(key)
	if !ok {
		return nil, fmt.Errorf("%s is required", key)
	}
	raw = strings.ReplaceAll(raw, " ", "")
	raw = strings.ReplaceAll(raw, ":", "")
	out, err := hex.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", key, err)
	}
	return out, nil
}

func parseUint64Env(key, raw string) (uint64, error) {
	if strings.TrimSpace(raw) == "" {
		return 0, fmt.Errorf("%s is required", key)
	}
	v, err := strconv.ParseUint(raw, 0, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return v, nil
}

func parseUint16Env(key, raw string) (uint16, error) {
	if strings.TrimSpace(raw) == "" {
		return 0, fmt.Errorf("%s is required", key)
	}
	v, err := strconv.ParseUint(raw, 0, 16)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return uint16(v), nil
}
