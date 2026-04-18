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

// Package config provides configuration types for Matter commissioning flows.
package config

// WiFiNetworkConfigHelper defines the interface for map and string representations of WiFi network configuration.
type WiFiNetworkConfigHelper interface {
	// Map returns a map representation of the WiFiNetworkConfig.
	Map() map[string]any
	// String returns a human-readable string representation of the WiFiNetworkConfig.
	String() string
}

// WiFiNetworkConfig holds the WiFi credentials required for Network Commissioning.
// 11.9.7.2. AddOrUpdateWiFiNetwork Command.
type WiFiNetworkConfig interface {
	WiFiNetworkConfigHelper
	// SSID returns the network SSID as an octet string.
	SSID() ([]byte, bool)
	// Credentials returns the network credentials (passphrase or PSK) as an octet string.
	Credentials() ([]byte, bool)
}
