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

package mockdevice

import (
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	"github.com/cybergarage/go-matter/matter/protocol/im"
)

// Network Commissioning cluster (0x0031) command IDs this mock responds to,
// independently reimplemented from (rather than importing)
// matter/cluster/networkcommissioning, matching this package's existing
// independence rationale for other clusters (see case_message.go).
// 11.8.7. Commands.
const (
	networkCommissioningClusterID  im.ClusterID = 0x0031
	addOrUpdateWiFiNetworkID       im.CommandID = 0x02
	networkConfigResponseCommandID im.CommandID = 0x05
	connectNetworkCommandID        im.CommandID = 0x06
	connectNetworkResponseID       im.CommandID = 0x07
)

// registerNetworkCommissioningHandlers wires AddOrUpdateWiFiNetwork and
// ConnectNetwork into srv, both unconditionally reporting success — this
// mock only needs commissionNetwork (matter/commissioning_impl.go) to
// observe a completed Wi-Fi provisioning step, not to actually track any
// network state. onConnectNetwork is invoked once ConnectNetwork is
// handled — the last PASE-phase step commissionOverPASE performs before
// moving on to CASE, so Device.serve's PASE Interaction Model loop knows
// not to stop any earlier than that.
func registerNetworkCommissioningHandlers(srv *imServer, onConnectNetwork func()) {
	srv.handleInvoke(defaultEndpointID, networkCommissioningClusterID, addOrUpdateWiFiNetworkID, func(map[uint8]tlv.Element) (im.CommandID, []byte, error) {
		fields, err := encodeNetworkingStatusSuccessFields()
		return networkConfigResponseCommandID, fields, err
	})
	srv.handleInvoke(defaultEndpointID, networkCommissioningClusterID, connectNetworkCommandID, func(map[uint8]tlv.Element) (im.CommandID, []byte, error) {
		fields, err := encodeNetworkingStatusSuccessFields()
		if err == nil && onConnectNetwork != nil {
			onConnectNetwork()
		}
		return connectNetworkResponseID, fields, err
	})
}

// encodeNetworkingStatusSuccessFields encodes the NetworkingStatus field
// (context tag 0) shared by NetworkConfigResponse and
// ConnectNetworkResponse, set to Success (0).
func encodeNetworkingStatusSuccessFields() ([]byte, error) {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewContextTag(1))
	enc.PutUnsigned1(tlv.NewContextTag(0), 0x00) // NetworkingStatus = Success
	if err := enc.EndContainer(); err != nil {
		return nil, err
	}
	return enc.Bytes(), nil
}
