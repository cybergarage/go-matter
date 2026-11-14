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

// Package generalcommissioning provides a client for the Matter General Commissioning cluster (0x0030).
// Reference: Matter Core Spec 1.5, Section 11.10.
package generalcommissioning

import (
	"errors"
	"fmt"

	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	"github.com/cybergarage/go-matter/matter/protocol/im"
	"github.com/cybergarage/go-matter/matter/protocol/session"
)

// ClusterID is the General Commissioning cluster identifier.
// 11.10. General Commissioning Cluster.
const ClusterID im.ClusterID = 0x0030

// Command IDs for the General Commissioning cluster.
// 11.10.7. Commands.
const (
	// ArmFailSafeCommandID arms (or disarms) the commissioning fail-safe timer.
	ArmFailSafeCommandID im.CommandID = 0x00
	// SetRegulatoryConfigCommandID sets the regulatory configuration for the device.
	SetRegulatoryConfigCommandID im.CommandID = 0x02
	// CommissioningCompleteCommandID signals the end of the commissioning session.
	CommissioningCompleteCommandID im.CommandID = 0x04
)

// Attribute IDs for the General Commissioning cluster.
// 11.10.5. Attributes.
const (
	// SupportsConcurrentConnectionAttributeID reports whether the Commissionee can
	// maintain the commissioning channel while also connecting to the operational network.
	SupportsConcurrentConnectionAttributeID im.AttributeID = 0x0004
)

// RegulatoryLocationType identifies the regulatory location type.
// 11.10.5.3. RegulatoryLocationType.
type RegulatoryLocationType uint8

const (
	// RegulatoryLocationTypeIndoor indicates the device is used indoors.
	RegulatoryLocationTypeIndoor RegulatoryLocationType = 0
	// RegulatoryLocationTypeOutdoor indicates the device is used outdoors.
	RegulatoryLocationTypeOutdoor RegulatoryLocationType = 1
	// RegulatoryLocationTypeIndoorOutdoor indicates the device can be used either indoors or outdoors.
	RegulatoryLocationTypeIndoorOutdoor RegulatoryLocationType = 2
)

// ArmFailSafe arms the commissioning fail-safe timer on the device.
// The device MUST respond with an ArmFailSafeResponse (command 0x01).
//
// ArmFailSafe TLV payload (spec section 11.10.7.1):
//
//	STRUCTURE {
//	  0: ExpiryLengthSeconds [UINT16]
//	  1: Breadcrumb          [UINT64]
//	}
//
// expiryLengthSeconds = 0 disarms the timer. The recommended value during commissioning is 60.
// breadcrumb is a value supplied by the commissioner to track commissioning progress.
// 11.10.7.1. ArmFailSafe Command.
func ArmFailSafe(sess session.SecureSession, endpointID im.EndpointID, expiryLengthSeconds uint16, breadcrumb uint64) error {
	fields, err := buildArmFailSafeFields(expiryLengthSeconds, breadcrumb)
	if err != nil {
		return fmt.Errorf("generalcommissioning: build ArmFailSafe fields: %w", err)
	}

	resp, err := im.Invoke(sess, endpointID, ClusterID, ArmFailSafeCommandID, fields)
	if err != nil {
		return fmt.Errorf("generalcommissioning: ArmFailSafe: %w", err)
	}
	// 11.10.7.3. ArmFailSafeResponse Command.
	return commissioningResponseError("ArmFailSafe", resp)
}

// SetRegulatoryConfig sets the regulatory domain configuration on the device.
//
// SetRegulatoryConfig TLV payload (spec section 11.10.7.4):
//
//	STRUCTURE {
//	  0: NewRegulatoryConfig [UINT8]  (RegulatoryLocationType)
//	  1: CountryCode         [UTF8]   (2-character ISO 3166-1 alpha-2)
//	  2: Breadcrumb          [UINT64]
//	}
//
// 11.10.7.4. SetRegulatoryConfig Command.
func SetRegulatoryConfig(sess session.SecureSession, endpointID im.EndpointID, locationType RegulatoryLocationType, countryCode string, breadcrumb uint64) error {
	fields, err := buildSetRegulatoryConfigFields(locationType, countryCode, breadcrumb)
	if err != nil {
		return fmt.Errorf("generalcommissioning: build SetRegulatoryConfig fields: %w", err)
	}

	resp, err := im.Invoke(sess, endpointID, ClusterID, SetRegulatoryConfigCommandID, fields)
	if err != nil {
		return fmt.Errorf("generalcommissioning: SetRegulatoryConfig: %w", err)
	}
	// 11.10.7.5. SetRegulatoryConfigResponse Command.
	return commissioningResponseError("SetRegulatoryConfig", resp)
}

// CommissioningComplete signals the end of the commissioning session, releasing the fail-safe.
// The device MUST respond with a CommissioningCompleteResponse (command 0x05).
// 11.10.7.7. CommissioningComplete Command.
func CommissioningComplete(sess session.SecureSession, endpointID im.EndpointID) error {
	// CommissioningComplete has no command fields.
	resp, err := im.Invoke(sess, endpointID, ClusterID, CommissioningCompleteCommandID, nil)
	if err != nil {
		return fmt.Errorf("generalcommissioning: CommissioningComplete: %w", err)
	}
	// 11.10.7.7. CommissioningCompleteResponse Command.
	return commissioningResponseError("CommissioningComplete", resp)
}

// buildArmFailSafeFields encodes the ArmFailSafe command fields as TLV.
func buildArmFailSafeFields(expiryLengthSeconds uint16, breadcrumb uint64) ([]byte, error) {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewContextTag(1))
	enc.PutUnsigned2(tlv.NewContextTag(0), expiryLengthSeconds)
	if err := enc.PutUnsigned(tlv.NewContextTag(1), breadcrumb); err != nil {
		return nil, err
	}
	if err := enc.EndContainer(); err != nil {
		return nil, err
	}
	return enc.Bytes(), nil
}

// buildSetRegulatoryConfigFields encodes the SetRegulatoryConfig command fields as TLV.
func buildSetRegulatoryConfigFields(locationType RegulatoryLocationType, countryCode string, breadcrumb uint64) ([]byte, error) {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewContextTag(1))
	enc.PutUnsigned1(tlv.NewContextTag(0), uint8(locationType))
	if err := enc.PutUTF81(tlv.NewContextTag(1), countryCode); err != nil {
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

// ErrCommissioning is a General Commissioning command which the device
// answered with an ErrorCode other than OK.
var ErrCommissioning = errors.New("generalcommissioning: the device refused the command")

// commissioningErrorNames are the names of the CommissioningErrorEnum
// values. 11.10.5.1. CommissioningErrorEnum.
var commissioningErrorNames = map[uint8]string{
	1: "ValueOutsideRange",
	2: "InvalidAuthentication",
	3: "NoFailSafe",
	4: "BusyWithOtherAdmin",
}

// commissioningResponseError returns the error an answer to a General
// Commissioning command carries: an IM status which is not success, or,
// in its response command, an ErrorCode which is not OK, with the
// DebugText. An answer with no response command (a status only) is taken
// as it is, as before. 11.10.7.3, 11.10.7.5, 11.10.7.7.
func commissioningResponseError(command string, resp *im.InvokeResponse) error {
	if !resp.IsSuccess() {
		return fmt.Errorf("generalcommissioning: %s failed: IM status 0x%02X, cluster status 0x%02X",
			command, resp.Status.IMStatus, resp.Status.ClusterStatus)
	}
	elem, ok := resp.Field(0)
	if !ok {
		return nil
	}
	code, ok := elem.Unsigned1()
	if !ok {
		return fmt.Errorf("generalcommissioning: %s: the response's ErrorCode is not a CommissioningErrorEnum", command)
	}
	if code == 0 {
		return nil
	}
	name, known := commissioningErrorNames[code]
	if !known {
		name = "unknown"
	}
	debugText := ""
	if text, ok := resp.Field(1); ok {
		if v, ok := text.UTF8(); ok && v != "" {
			debugText = ": " + v
		}
	}
	return fmt.Errorf("%w: %s: ErrorCode=%d (%s)%s", ErrCommissioning, command, code, name, debugText)
}
