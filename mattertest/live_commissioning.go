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

// defaultAdminVendorID is the CSA-reserved "Test Vendor 1" ID, used as the
// commissioner's AdminVendorId unless MATTER_TEST_ADMIN_VENDOR_ID overrides it.
const defaultAdminVendorID uint16 = 0xFFF1

// defaultOperationalIPK is a fixed 16-byte test Identity Protection Key, used
// unless MATTER_TEST_OPERATIONAL_IPK_HEX overrides it. Any value works here:
// the IPK is established by the commissioner itself (it is not a property of
// the device), it just has to be internally consistent between AddNOC and
// the CASE session that follows it.
var defaultOperationalIPK = []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}

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

// loadLiveCommissioningScenarioFromEnv builds a commissioning scenario for
// TestCommissioner. Only what actually depends on the physical device or
// its network is required from the environment:
//
//   - MATTER_TEST_MANUAL_PAIRING_CODE — the device's Manual Pairing Code
//     (MPC), the same 11/21-digit code chip-tool takes as the last argument
//     of `pairing code-wifi <node-id> <ssid> <password> <MPC>`.
//   - MATTER_TEST_WIFI_SSID / MATTER_TEST_WIFI_PASSWORD — the Wi-Fi network to
//     hand the device during commissioning (both or neither).
//
// Everything else (administrator identity, fabric ID, root/NOC certificates
// and keys, IPK, vendor ID) is commissioner-side configuration, not a
// property of the device, so each falls back to a fixed embedded test
// default (see mattertest/config.go's NewAdministratorConfig and the
// defaultAdminVendorID/defaultOperationalIPK constants above) unless
// explicitly overridden by its environment variable. This mirrors chip-tool's
// own minimal invocation:
//
//	MATTER_TEST_COMMISSIONER_LIVE=1 \
//	MATTER_TEST_MANUAL_PAIRING_CODE=$MPC \
//	MATTER_TEST_WIFI_SSID=$SSID MATTER_TEST_WIFI_PASSWORD=$PASS \
//	go test ./mattertest/... -run TestCommissioner -v
func loadLiveCommissioningScenarioFromEnv() (liveCommissioningScenario, error) {
	if os.Getenv("MATTER_TEST_COMMISSIONER_LIVE") != "1" {
		return liveCommissioningScenario{}, errLiveCommissioningDisabled
	}

	pairingCodeStr, err := requireEnv("MATTER_TEST_MANUAL_PAIRING_CODE")
	if err != nil {
		return liveCommissioningScenario{}, err
	}
	pairingCode, err := encoding.NewPairingCodeFromString(pairingCodeStr)
	if err != nil {
		return liveCommissioningScenario{}, fmt.Errorf("MATTER_TEST_MANUAL_PAIRING_CODE: %w", err)
	}

	adminNodeID, err := envUint64OrDefault("MATTER_TEST_ADMIN_NODE_ID", testAdministratorNodeID)
	if err != nil {
		return liveCommissioningScenario{}, err
	}
	fabricID, err := envUint64OrDefault("MATTER_TEST_FABRIC_ID", testAdministratorFabricID)
	if err != nil {
		return liveCommissioningScenario{}, err
	}
	caseAdminNodeID, err := envUint64OrDefault("MATTER_TEST_CASE_ADMIN_NODE_ID", adminNodeID)
	if err != nil {
		return liveCommissioningScenario{}, err
	}
	if adminNodeID != caseAdminNodeID {
		return liveCommissioningScenario{}, fmt.Errorf("administrator node ID (0x%016X) must match CASE admin node ID (0x%016X)", adminNodeID, caseAdminNodeID)
	}
	adminVendorID, err := envUint16OrDefault("MATTER_TEST_ADMIN_VENDOR_ID", defaultAdminVendorID)
	if err != nil {
		return liveCommissioningScenario{}, err
	}
	ipk, err := envHexOrDefault("MATTER_TEST_OPERATIONAL_IPK_HEX", defaultOperationalIPK)
	if err != nil {
		return liveCommissioningScenario{}, err
	}

	adminRootCert, err := envBlobOrDefault("MATTER_TEST_ADMIN_ROOT_CERT", testAdminRootCertPEM)
	if err != nil {
		return liveCommissioningScenario{}, err
	}
	adminRootPrivateKey, err := envBlobOrDefault("MATTER_TEST_ADMIN_ROOT_PRIVATE_KEY", testAdminRootKeyPEM)
	if err != nil {
		return liveCommissioningScenario{}, err
	}
	adminNOC, err := envBlobOrDefault("MATTER_TEST_ADMIN_NOC", testAdminNOCPEM)
	if err != nil {
		return liveCommissioningScenario{}, err
	}
	adminPrivateKey, err := envBlobOrDefault("MATTER_TEST_ADMIN_PRIVATE_KEY", testAdminPrivateKeyPEM)
	if err != nil {
		return liveCommissioningScenario{}, err
	}
	// No embedded default: the test certificate chain has no intermediate.
	adminICAC, err := optionalEnvBlob("MATTER_TEST_ADMIN_ICAC")
	if err != nil {
		return liveCommissioningScenario{}, err
	}

	adminCfgOpts := []config.AdministratorConfigOption{
		config.WithAdministratorNodeID(adminNodeID),
		config.WithAdministratorFabricID(fabricID),
		config.WithAdministratorRootCertificate(adminRootCert),
		config.WithAdministratorRootPrivateKey(adminRootPrivateKey),
		config.WithAdministratorNOC(adminNOC),
		config.WithAdministratorPrivateKey(adminPrivateKey),
	}
	if len(adminICAC) != 0 {
		adminCfgOpts = append(adminCfgOpts, config.WithAdministratorICAC(adminICAC))
	}
	operationalCfgOpts := []config.OperationalCredentialsConfigOption{
		config.WithIPK(ipk),
		config.WithCASEAdminNodeID(caseAdminNodeID),
		config.WithAdminVendorID(adminVendorID),
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

// optionalEnvBlob reads a PEM/DER blob from <prefix>_FILE or <prefix>_PEM,
// returning (nil, nil) if neither is set.
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

// envBlobOrDefault is optionalEnvBlob, falling back to def when neither
// <prefix>_FILE nor <prefix>_PEM is set.
func envBlobOrDefault(prefix string, def []byte) ([]byte, error) {
	b, err := optionalEnvBlob(prefix)
	if err != nil {
		return nil, err
	}
	if len(b) != 0 {
		return b, nil
	}
	return def, nil
}

// envHexOrDefault parses key as hex (ignoring spaces/colons), falling back
// to def when key is unset.
func envHexOrDefault(key string, def []byte) ([]byte, error) {
	raw, ok := lookupTrimmedEnv(key)
	if !ok {
		return def, nil
	}
	raw = strings.ReplaceAll(raw, " ", "")
	raw = strings.ReplaceAll(raw, ":", "")
	out, err := hex.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", key, err)
	}
	return out, nil
}

// envUint64OrDefault parses key as a uint64 (accepting 0x-prefixed hex),
// falling back to def when key is unset.
func envUint64OrDefault(key string, def uint64) (uint64, error) {
	raw, ok := lookupTrimmedEnv(key)
	if !ok {
		return def, nil
	}
	v, err := strconv.ParseUint(raw, 0, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return v, nil
}

// envUint16OrDefault parses key as a uint16 (accepting 0x-prefixed hex),
// falling back to def when key is unset.
func envUint16OrDefault(key string, def uint16) (uint16, error) {
	raw, ok := lookupTrimmedEnv(key)
	if !ok {
		return def, nil
	}
	v, err := strconv.ParseUint(raw, 0, 16)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return uint16(v), nil
}
