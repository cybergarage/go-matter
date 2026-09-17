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

// Package networkcommissioning provides a client for the Matter Network
// Commissioning cluster (0x0031), covering Wi-Fi network provisioning.
// Reference: Matter Core Spec 1.5, Section 11.8.
package networkcommissioning

import (
	"errors"
	"fmt"

	"github.com/cybergarage/go-matter/matter/encoding/tlv"
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

// NetworkingStatusSuccess is the success value of NetworkConfigResponse and
// ConnectNetworkResponse's NetworkingStatus field.
// 11.8.5.2. NetworkCommissioningStatusEnum.
const NetworkingStatusSuccess uint8 = 0

// ErrNotImplemented is returned by network types this package does not
// support (Thread and network scanning are out of scope for commissioning
// over Wi-Fi, the only flow this codebase drives).
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
func AddOrUpdateWiFiNetwork(sess session.SecureSession, ep im.EndpointID, ssid, credentials []byte, breadcrumb uint64) error {
	fields, err := buildAddOrUpdateWiFiNetworkFields(ssid, credentials, breadcrumb)
	if err != nil {
		return fmt.Errorf("networkcommissioning: build AddOrUpdateWiFiNetwork fields: %w", err)
	}
	resp, err := im.Invoke(sess, ep, ClusterID, AddOrUpdateWiFiNetworkCommandID, fields)
	if err != nil {
		return fmt.Errorf("networkcommissioning: AddOrUpdateWiFiNetwork: %w", err)
	}
	if !resp.IsSuccess() {
		return invokeStatusError("AddOrUpdateWiFiNetwork", resp)
	}
	return networkConfigResponseError("AddOrUpdateWiFiNetwork", resp)
}

// AddOrUpdateThreadNetwork provisions Thread network credentials (TLV
// dataset) onto the device. Not implemented — this codebase only drives
// Wi-Fi commissioning.
// 11.8.7.4. AddOrUpdateThreadNetwork Command.
func AddOrUpdateThreadNetwork(_ session.SecureSession, _ im.EndpointID, _ []byte, _ uint64) error {
	return ErrNotImplemented
}

// ConnectNetwork instructs the device to connect to the specified network.
// networkID is the SSID (Wi-Fi) as an octet string.
//
// ConnectNetwork TLV payload (spec section 11.8.7.7):
//
//	STRUCTURE {
//	  0: NetworkID  [OCTET_STRING]
//	  1: Breadcrumb [UINT64] (optional)
//	}
//
// 11.8.7.7. ConnectNetwork Command.
func ConnectNetwork(sess session.SecureSession, ep im.EndpointID, networkID []byte, breadcrumb uint64) error {
	fields, err := buildConnectNetworkFields(networkID, breadcrumb)
	if err != nil {
		return fmt.Errorf("networkcommissioning: build ConnectNetwork fields: %w", err)
	}
	resp, err := im.Invoke(sess, ep, ClusterID, ConnectNetworkCommandID, fields)
	if err != nil {
		return fmt.Errorf("networkcommissioning: ConnectNetwork: %w", err)
	}
	if !resp.IsSuccess() {
		return invokeStatusError("ConnectNetwork", resp)
	}
	return networkConfigResponseError("ConnectNetwork", resp)
}

func buildAddOrUpdateWiFiNetworkFields(ssid, credentials []byte, breadcrumb uint64) ([]byte, error) {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewContextTag(1))
	if err := enc.PutOctet(tlv.NewContextTag(0), ssid); err != nil {
		return nil, err
	}
	if err := enc.PutOctet(tlv.NewContextTag(1), credentials); err != nil {
		return nil, err
	}
	if err := enc.PutUnsigned(tlv.NewContextTag(2), breadcrumb); err != nil {
		return nil, err
	}
	if err := enc.EndContainer(); err != nil {
		return nil, err
	}
	return enc.Bytes(), nil
}

func buildConnectNetworkFields(networkID []byte, breadcrumb uint64) ([]byte, error) {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewContextTag(1))
	if err := enc.PutOctet(tlv.NewContextTag(0), networkID); err != nil {
		return nil, err
	}
	if err := enc.PutUnsigned(tlv.NewContextTag(1), breadcrumb); err != nil {
		return nil, err
	}
	if err := enc.EndContainer(); err != nil {
		return nil, err
	}
	return enc.Bytes(), nil
}

// networkConfigResponseError inspects the NetworkingStatus field (context
// tag 0, shared by NetworkConfigResponse and ConnectNetworkResponse) and
// returns a descriptive error if it is not Success.
func networkConfigResponseError(command string, resp *im.InvokeResponse) error {
	elem, ok := resp.Field(0)
	if !ok {
		return nil // no NetworkingStatus field: nothing to check.
	}
	status, ok := elem.Unsigned1()
	if !ok || status == NetworkingStatusSuccess {
		return nil
	}
	debugText := ""
	if textElem, ok := resp.Field(2); ok {
		if s, ok := textElem.UTF8(); ok {
			debugText = s
		}
	}
	return fmt.Errorf("networkcommissioning: %s failed: NetworkingStatus=%d %s", command, status, debugText)
}

func invokeStatusError(command string, resp *im.InvokeResponse) error {
	return fmt.Errorf("networkcommissioning: %s failed: IM status 0x%02X, cluster status 0x%02X",
		command, resp.Status.IMStatus, resp.Status.ClusterStatus)
}
