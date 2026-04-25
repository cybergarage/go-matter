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
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadLiveCommissioningScenarioFromEnvDisabled(t *testing.T) {
	clearLiveEnv(t)

	_, err := loadLiveCommissioningScenarioFromEnv()
	if !errors.Is(err, errLiveCommissioningDisabled) {
		t.Fatalf("loadLiveCommissioningScenarioFromEnv() error = %v, want errLiveCommissioningDisabled", err)
	}
}

func TestLoadLiveCommissioningScenarioFromEnvMissingRequired(t *testing.T) {
	clearLiveEnv(t)
	t.Setenv("MATTER_TEST_COMMISSIONER_LIVE", "1")

	_, err := loadLiveCommissioningScenarioFromEnv()
	if err == nil || !strings.Contains(err.Error(), "MATTER_TEST_PAIRING_CODE") {
		t.Fatalf("loadLiveCommissioningScenarioFromEnv() error = %v, want missing pairing-code error", err)
	}
}

func TestLoadLiveCommissioningScenarioFromEnvInvalidPath(t *testing.T) {
	clearLiveEnv(t)
	setRequiredLiveEnv(t)
	t.Setenv("MATTER_TEST_ADMIN_ROOT_CERT_FILE", filepath.Join(t.TempDir(), "missing.pem"))

	_, err := loadLiveCommissioningScenarioFromEnv()
	if err == nil || !strings.Contains(err.Error(), "MATTER_TEST_ADMIN_ROOT_CERT_FILE") {
		t.Fatalf("loadLiveCommissioningScenarioFromEnv() error = %v, want invalid-path error", err)
	}
}

func TestLoadLiveCommissioningScenarioFromEnvNodeIDMismatch(t *testing.T) {
	clearLiveEnv(t)
	setRequiredLiveEnv(t)
	t.Setenv("MATTER_TEST_CASE_ADMIN_NODE_ID", "0x2")

	_, err := loadLiveCommissioningScenarioFromEnv()
	if err == nil || !strings.Contains(err.Error(), "must match CASE admin node ID") {
		t.Fatalf("loadLiveCommissioningScenarioFromEnv() error = %v, want node-ID mismatch", err)
	}
}

func TestLoadLiveCommissioningScenarioFromEnvWiFiOptional(t *testing.T) {
	clearLiveEnv(t)
	setRequiredLiveEnv(t)

	scenario, err := loadLiveCommissioningScenarioFromEnv()
	if err != nil {
		t.Fatalf("loadLiveCommissioningScenarioFromEnv() error = %v", err)
	}
	if scenario.WiFi != nil {
		t.Fatalf("scenario.WiFi = %#v, want nil", scenario.WiFi)
	}

	t.Setenv("MATTER_TEST_WIFI_SSID", "ssid")
	t.Setenv("MATTER_TEST_WIFI_PASSWORD", "password")
	scenario, err = loadLiveCommissioningScenarioFromEnv()
	if err != nil {
		t.Fatalf("loadLiveCommissioningScenarioFromEnv() with Wi-Fi error = %v", err)
	}
	if scenario.WiFi == nil {
		t.Fatal("scenario.WiFi = nil, want non-nil")
	}
}

func clearLiveEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"MATTER_TEST_COMMISSIONER_LIVE",
		"MATTER_TEST_SCENARIO_NAME",
		"MATTER_TEST_PAIRING_CODE",
		"MATTER_TEST_ADMIN_NODE_ID",
		"MATTER_TEST_FABRIC_ID",
		"MATTER_TEST_ADMIN_ROOT_CERT_FILE",
		"MATTER_TEST_ADMIN_ROOT_CERT_PEM",
		"MATTER_TEST_ADMIN_NOC_FILE",
		"MATTER_TEST_ADMIN_NOC_PEM",
		"MATTER_TEST_ADMIN_ICAC_FILE",
		"MATTER_TEST_ADMIN_ICAC_PEM",
		"MATTER_TEST_ADMIN_PRIVATE_KEY_FILE",
		"MATTER_TEST_ADMIN_PRIVATE_KEY_PEM",
		"MATTER_TEST_OPERATIONAL_ROOT_CERT_FILE",
		"MATTER_TEST_OPERATIONAL_ROOT_CERT_PEM",
		"MATTER_TEST_OPERATIONAL_NOC_FILE",
		"MATTER_TEST_OPERATIONAL_NOC_PEM",
		"MATTER_TEST_OPERATIONAL_ICAC_FILE",
		"MATTER_TEST_OPERATIONAL_ICAC_PEM",
		"MATTER_TEST_OPERATIONAL_IPK_HEX",
		"MATTER_TEST_CASE_ADMIN_NODE_ID",
		"MATTER_TEST_ADMIN_VENDOR_ID",
		"MATTER_TEST_WIFI_SSID",
		"MATTER_TEST_WIFI_PASSWORD",
	} {
		t.Setenv(key, "")
	}
}

func setRequiredLiveEnv(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	adminRoot := writeTempFile(t, dir, "admin-root.pem", "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
	adminNOC := writeTempFile(t, dir, "admin-noc.pem", "-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----\n")
	adminKey := writeTempFile(t, dir, "admin-key.pem", "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n")
	operRoot := writeTempFile(t, dir, "oper-root.pem", "-----BEGIN CERTIFICATE-----\nMIID\n-----END CERTIFICATE-----\n")
	operNOC := writeTempFile(t, dir, "oper-noc.pem", "-----BEGIN CERTIFICATE-----\nMIIE\n-----END CERTIFICATE-----\n")

	t.Setenv("MATTER_TEST_COMMISSIONER_LIVE", "1")
	t.Setenv("MATTER_TEST_PAIRING_CODE", "2167-692-8175")
	t.Setenv("MATTER_TEST_ADMIN_NODE_ID", "0x1")
	t.Setenv("MATTER_TEST_FABRIC_ID", "0x2")
	t.Setenv("MATTER_TEST_ADMIN_ROOT_CERT_FILE", adminRoot)
	t.Setenv("MATTER_TEST_ADMIN_NOC_FILE", adminNOC)
	t.Setenv("MATTER_TEST_ADMIN_PRIVATE_KEY_FILE", adminKey)
	t.Setenv("MATTER_TEST_OPERATIONAL_ROOT_CERT_FILE", operRoot)
	t.Setenv("MATTER_TEST_OPERATIONAL_NOC_FILE", operNOC)
	t.Setenv("MATTER_TEST_OPERATIONAL_IPK_HEX", "00112233445566778899AABBCCDDEEFF")
	t.Setenv("MATTER_TEST_CASE_ADMIN_NODE_ID", "0x1")
	t.Setenv("MATTER_TEST_ADMIN_VENDOR_ID", "0xFFF1")
}

func writeTempFile(t *testing.T, dir, name, contents string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("os.WriteFile(%s) error = %v", path, err)
	}
	return path
}
