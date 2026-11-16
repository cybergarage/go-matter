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

package config

import (
	"encoding/base64"
	"strings"
	"testing"
)

// The secrets of a configuration are never shown by its Map and String,
// and are still read with their accessors.
func TestConfigurationsRedactSecrets(t *testing.T) {
	privateKey := []byte("operational private key")
	rootPrivateKey := []byte("root private key")
	admin := NewAdministratorConfig(
		WithAdministratorPrivateKey(privateKey),
		WithAdministratorRootPrivateKey(rootPrivateKey),
	)
	for _, key := range []string{"privateKey", "rootPrivateKey"} {
		if got := admin.Map()[key]; got != Redacted {
			t.Fatalf("AdministratorConfig.Map()[%s] = %#v, want it redacted", key, got)
		}
	}
	for _, secret := range [][]byte{privateKey, rootPrivateKey} {
		if s := admin.String(); strings.Contains(s, base64.StdEncoding.EncodeToString(secret)) {
			t.Fatalf("AdministratorConfig.String() = %s, shows a private key", s)
		}
	}
	if got, ok := admin.PrivateKey(); !ok || string(got) != string(privateKey) {
		t.Fatalf("PrivateKey() = %q, %v", got, ok)
	}

	password := []byte("correct horse battery")
	wifi := NewWiFiNetworkConfig(WithSSID([]byte("home")), WithCredentials(password))
	if got := wifi.Map()["credentials"]; got != Redacted {
		t.Fatalf("WiFiNetworkConfig.Map()[credentials] = %#v, want it redacted", got)
	}
	if s := wifi.String(); strings.Contains(s, base64.StdEncoding.EncodeToString(password)) || strings.Contains(s, string(password)) {
		t.Fatalf("WiFiNetworkConfig.String() = %s, shows the password", s)
	}
	if got, ok := wifi.Credentials(); !ok || string(got) != string(password) {
		t.Fatalf("Credentials() = %q, %v", got, ok)
	}
}
