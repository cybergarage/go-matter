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

// defaultEndpointID is the root/commissioning endpoint (0), used for every
// cluster this server handles.
const defaultEndpointID im.EndpointID = 0

// General Commissioning cluster (0x0030) command/attribute IDs, per Matter
// Core Spec 11.10 (confirmed against connectedhomeip's
// general-commissioning-cluster.xml).
const (
	generalCommissioningClusterID           im.ClusterID   = 0x0030
	armFailSafeCommandID                    im.CommandID   = 0x00
	armFailSafeResponseCommandID            im.CommandID   = 0x01
	commissioningCompleteCommandID          im.CommandID   = 0x04
	commissioningCompleteResponseCommandID  im.CommandID   = 0x05
	supportsConcurrentConnectionAttributeID im.AttributeID = 0x0004
)

// registerGeneralCommissioningHandlers wires ArmFailSafe, the
// SupportsConcurrentConnection attribute read, and CommissioningComplete
// into srv. onCommissioningComplete is invoked once CommissioningComplete
// is handled (the strong end-to-end assertion hook for the full mock test).
func registerGeneralCommissioningHandlers(srv *imServer, onCommissioningComplete func()) {
	srv.handleInvoke(defaultEndpointID, generalCommissioningClusterID, armFailSafeCommandID, func(map[uint8]tlv.Element) (im.CommandID, []byte, error) {
		fields, err := encodeGeneralCommissioningResponseFields()
		return armFailSafeResponseCommandID, fields, err
	})

	srv.handleRead(defaultEndpointID, generalCommissioningClusterID, supportsConcurrentConnectionAttributeID, func() (func(enc tlv.Encoder) error, error) {
		return boolAttribute(true), nil
	})

	srv.handleInvoke(defaultEndpointID, generalCommissioningClusterID, commissioningCompleteCommandID, func(map[uint8]tlv.Element) (im.CommandID, []byte, error) {
		fields, err := encodeGeneralCommissioningResponseFields()
		if err == nil && onCommissioningComplete != nil {
			onCommissioningComplete()
		}
		return commissioningCompleteResponseCommandID, fields, err
	})
}

// encodeGeneralCommissioningResponseFields builds the common
// {ErrorCode: OK, DebugText: ""} CommandFields shared by
// ArmFailSafeResponse and CommissioningCompleteResponse.
func encodeGeneralCommissioningResponseFields() ([]byte, error) {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewContextTag(1))
	enc.PutUnsigned1(tlv.NewContextTag(0), 0x00) // ErrorCode = OK
	if err := enc.PutUTF81(tlv.NewContextTag(1), ""); err != nil {
		return nil, err
	}
	if err := enc.EndContainer(); err != nil {
		return nil, err
	}
	return enc.Bytes(), nil
}
