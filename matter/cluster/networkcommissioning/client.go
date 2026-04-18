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

// Package networkcommissioning provides a client skeleton for the Matter
// Network Commissioning cluster (0x0031).
// Reference: Matter Core Spec 1.5, Section 11.8.
//
// # Implementation status
//
// This package provides the API skeleton for Wi-Fi and Thread network credential
// provisioning. Full implementation requires:
//
//   - Wi-Fi credentials (SSID + passphrase) encoding in TLV
//   - Thread credentials (TLV-encoded dataset) encoding
//   - Network scanning result parsing
//   - ConnectNetwork response handling with networkingStatus codes
//
// TODO: Implement full Wi-Fi and Thread network credential provisioning.
package networkcommissioning

import (
	"errors"

	"github.com/cybergarage/go-matter/matter/protocol/im"
	"github.com/cybergarage/go-matter/matter/protocol/session"
)

// ClusterID is the Network Commissioning cluster identifier.
// 11.8. Network Commissioning Cluster.
const ClusterID im.ClusterID = 0x0031

// Command IDs for the Network Commissioning cluster.
// 11.8.7. Commands.
const (
	// ScanNetworksCommandID scans for available networks.
	ScanNetworksCommandID im.CommandID = 0x00
	// AddOrUpdateWiFiNetworkCommandID adds or updates a Wi-Fi network credential.
	AddOrUpdateWiFiNetworkCommandID im.CommandID = 0x02
	// AddOrUpdateThreadNetworkCommandID adds or updates a Thread network credential.
	AddOrUpdateThreadNetworkCommandID im.CommandID = 0x03
	// RemoveNetworkCommandID removes a network credential.
	RemoveNetworkCommandID im.CommandID = 0x04
	// ConnectNetworkCommandID initiates connection to the specified network.
	ConnectNetworkCommandID im.CommandID = 0x06
	// ReorderNetworkCommandID reorders the network priority list.
	ReorderNetworkCommandID im.CommandID = 0x08
)

// ErrNotImplemented is returned by unimplemented network commissioning operations.
var ErrNotImplemented = errors.New("networkcommissioning: not yet implemented")

// AddOrUpdateWiFiNetwork provisions Wi-Fi credentials onto the device.
//
// AddOrUpdateWiFiNetwork TLV payload (spec section 11.8.7.3):
//
//	STRUCTURE {
//	  0: SSID       [OCTET_STRING]
//	  1: Credentials [OCTET_STRING]   (passphrase or PSK)
//	  2: Breadcrumb [UINT64] (optional)
//	}
//
// 11.8.7.3. AddOrUpdateWiFiNetwork Command.
//
// TODO: Implement Wi-Fi credential TLV encoding and response parsing.
func AddOrUpdateWiFiNetwork(_ session.SecureSession, _ im.EndpointID, _ []byte, _ []byte, _ uint64) error {
	return ErrNotImplemented
}

// AddOrUpdateThreadNetwork provisions Thread network credentials (TLV dataset) onto the device.
// 11.8.7.4. AddOrUpdateThreadNetwork Command.
//
// TODO: Implement Thread dataset TLV encoding and response parsing.
func AddOrUpdateThreadNetwork(_ session.SecureSession, _ im.EndpointID, _ []byte, _ uint64) error {
	return ErrNotImplemented
}

// ConnectNetwork instructs the device to connect to the specified network.
// networkID is the SSID (Wi-Fi) or Extended PAN ID (Thread) as an octet string.
// 11.8.7.7. ConnectNetwork Command.
//
// TODO: Implement with response parsing and networkingStatus validation.
func ConnectNetwork(_ session.SecureSession, _ im.EndpointID, _ []byte, _ uint64) error {
	return ErrNotImplemented
}
