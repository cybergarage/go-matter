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

// WiFiNetworkConfigOption defines a functional option for configuring WiFiNetworkConfig.
type WiFiNetworkConfigOption func(*wifiNetworkConfig)

// WithSSID sets the network SSID.
func WithSSID(ssid []byte) WiFiNetworkConfigOption {
	return func(c *wifiNetworkConfig) {
		c.ssid = ssid
	}
}

// WithCredentials sets the network credentials (passphrase or PSK).
func WithCredentials(credentials []byte) WiFiNetworkConfigOption {
	return func(c *wifiNetworkConfig) {
		c.credentials = credentials
	}
}

type wifiNetworkConfig struct {
	ssid        []byte
	credentials []byte
}

func newWiFiNetworkConfig(opts ...WiFiNetworkConfigOption) *wifiNetworkConfig {
	c := &wifiNetworkConfig{}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// NewWiFiNetworkConfig creates a new WiFiNetworkConfig with the provided options.
func NewWiFiNetworkConfig(opts ...WiFiNetworkConfigOption) WiFiNetworkConfig {
	return newWiFiNetworkConfig(opts...)
}

func (c *wifiNetworkConfig) SSID() ([]byte, bool) {
	if c.ssid == nil {
		return nil, false
	}
	return c.ssid, true
}

func (c *wifiNetworkConfig) Credentials() ([]byte, bool) {
	if c.credentials == nil {
		return nil, false
	}
	return c.credentials, true
}

func (c *wifiNetworkConfig) Map() map[string]any {
	m := make(map[string]any)
	if c.ssid != nil {
		m["ssid"] = c.ssid
	}
	if c.credentials != nil {
		m["credentials"] = c.credentials
	}
	return m
}

func (c *wifiNetworkConfig) String() string {
	return json.MustMarshal(c.Map())
}
