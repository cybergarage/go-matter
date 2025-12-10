// Copyright (C) 2024 The go-matter Authors. All rights reserved.
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

package mdns

import (
	"strings"

	"github.com/cybergarage/go-matter/matter/types"
	"github.com/cybergarage/go-mdns/mdns"
	"github.com/cybergarage/go-mdns/mdns/dns"
)

// commissioningNode represents a commissioning node.
type commissioningNode struct {
	mdns.Service
}

// NewCommissioningNodeWithMessage returns a new commissioning node with a mDNS message.
func NewCommissioningNodeWithMessage(msg dns.Message) (CommissionableNode, error) {
	service, err := mdns.NewService(
		mdns.WithServiceMessage(msg),
	)
	if err != nil {
		return nil, err
	}
	return NewCommissioningNodeWithService(service), nil
}

// NewCommissioningNodeWithService returns a new commissioning node with a mDNS service.
func NewCommissioningNodeWithService(service mdns.Service) CommissionableNode {
	node := &commissioningNode{
		Service: service,
	}
	return node
}

// LookupSubtype returns a subtype for the specified prefix.
func (node *commissioningNode) LookupSubtype(prefix string) (string, bool) {
	record, ok := node.Service.LookupResourceByNamePrefix(prefix)
	if !ok {
		return "", false
	}
	names := strings.Split(record.Name(), ".")
	if len(names) < 1 {
		return "", false
	}
	return names[0][len(prefix):], true
}

// LookupTxtAttribute looks up a TXT attribute by name.
func (node *commissioningNode) LookupTxtAttribute(name string) (string, bool) {
	attr, ok := node.Service.LookupResourceAttribute(name)
	if !ok {
		return "", false
	}
	return attr.Value(), true
}

func (node *commissioningNode) appendLookupSubtype(records []string, name string) []string {
	v, ok := node.LookupSubtype(name)
	if !ok {
		return records
	}
	return append(records, v)
}

func (node *commissioningNode) appendLookupTxtAttribute(records []string, name string) []string {
	v, ok := node.LookupTxtAttribute(name)
	if !ok {
		return records
	}
	return append(records, v)
}

// Discriminator returns a full discriminator or short discriminator.
// 4.3.1.5. TXT key for discriminator (D).
func (node *commissioningNode) Discriminator() (Discriminator, bool) {
	desc, ok := node.FullDiscriminator()
	if ok {
		return desc, true
	}
	return node.ShortDiscriminator()
}

// FullDiscriminator returns a full 12-bit discriminator.
// 4.3.1.3. Commissioning Subtypes (_L).
func (node *commissioningNode) FullDiscriminator() (Discriminator, bool) {
	v, ok := node.LookupTxtAttribute(TxtRecordDiscriminator)
	if !ok {
		v, ok = node.LookupSubtype(SubtypeDiscriminatorLong)
		if !ok {
			return 0, false
		}
	}
	desc, err := types.NewDiscriminatorFrom(v)
	if err != nil {
		return 0, false
	}
	return desc, true
}

// ShortDiscriminator returns a short 4-bit discriminator.
// 4.3.1.3. Commissioning Subtypes (_S).
func (node *commissioningNode) ShortDiscriminator() (Discriminator, bool) {
	v, ok := node.LookupSubtype(SubtypeDiscriminatorShort)
	if !ok {
		return 0, false
	}
	desc, err := types.NewDiscriminatorFrom(v)
	if err != nil {
		return 0, false
	}
	return desc, true
}

// VendorProductID returns a vendor and product ID.
// 4.3.1.6. TXT key for Vendor ID and Product ID (VP).
func (node *commissioningNode) VendorProductID() (string, string, bool) {
	splitVenderProductID := func(vp string) (string, string, bool) {
		vpList := strings.Split(vp, "+")
		if len(vpList) < 1 {
			return vpList[0], "", true
		}
		return vpList[0], vpList[1], true
	}
	vp, ok := node.LookupTxtAttribute(TxtRecordVendorProductID)
	if !ok || len(vp) == 0 {
		return "", "", false
	}
	return splitVenderProductID(vp)
}

// VendorID returns a vendor and product ID.
// 4.3.1.3. Commissioning Subtypes (_V)
// 4.3.1.6. TXT key for Vendor ID and Product ID (VP).
func (node *commissioningNode) VendorID() (string, bool) {
	venderID, _, ok := node.VendorProductID()
	if ok {
		return venderID, true
	}
	return node.LookupSubtype(SubtypeVendorID)
}

// ProductID returns a vendor and product ID.
// 4.3.1.6. TXT key for Vendor ID and Product ID (VP).
func (node *commissioningNode) ProductID() (string, bool) {
	_, productID, ok := node.VendorProductID()
	if !ok {
		return "", false
	}
	return productID, true
}

// CommissioningMode returns a commissioning mode.
// 4.3.1.3. Commissioning Subtypes (_CM)
// 4.3.1.7. TXT key for commissioning mode (CM).
func (node *commissioningNode) CommissioningMode() (string, bool) {
	cmFrom := func(cms string) (string, bool) {
		if len(cms) == 0 {
			return CommissioningModeNone, true
		}
		return cms, true
	}

	var records []string
	records = node.appendLookupTxtAttribute(records, TxtRecordCommissioningMode)
	records = node.appendLookupSubtype(records, SubtypeCommissioningMode)

	for _, cms := range records {
		cm, ok := cmFrom(cms)
		if ok {
			return cm, true
		}
	}

	return CommissioningModeNone, false
}

// DeviceType returns a device type.
// 4.3.1.3. Commissioning Subtypes (_T)
// 4.3.1.8. TXT key for device type (DT).
func (node *commissioningNode) DeviceType() (DeviceType, bool) {
	deviceTypeFrom := func(dts string) (DeviceType, bool) {
		dt, err := NewDeviceTypeFromString(dts)
		if err != nil {
			return DeviceTypeUnknown, false
		}
		return dt, true
	}

	var records []string
	records = node.appendLookupTxtAttribute(records, TxtRecordDeviceType)
	records = node.appendLookupSubtype(records, SubtypeDeviceType)

	for _, dts := range records {
		dt, ok := deviceTypeFrom(dts)
		if ok {
			return dt, true
		}
	}

	return DeviceTypeUnknown, false
}

// DeviceName returns a device name.
// 4.3.1.9. TXT key for device name (DN).
func (node *commissioningNode) DeviceName() (string, bool) {
	return node.LookupTxtAttribute(TxtRecordDeviceName)
}

// RotatingDeviceID returns a rotating device identifier.
// 4.3.1.10. TXT key for rotating device identifier (RI).
func (node *commissioningNode) RotatingDeviceID() (string, bool) {
	return node.LookupTxtAttribute(TxtRecordRotatingDeviceID)
}

// PairingHint returns a pairing hint.
// 4.3.1.11. TXT key for pairing hint (PH).
func (node *commissioningNode) PairingHint() (PairingHint, bool) {
	phs, ok := node.LookupTxtAttribute(TxtRecordPairingHint)
	if !ok {
		return PairingHintNone, false
	}
	ph, err := NewPairingHintFromString(phs)
	if err != nil {
		return PairingHintNone, false
	}
	return ph, true
}

// PairingInstructions returns a pairing instructions.
// 4.3.1.12. TXT key for pairing instructions (PI).
func (node *commissioningNode) PairingInstructions() (string, bool) {
	return node.LookupTxtAttribute(TxtRecordPairingInstruction)
}

// String returns the string representation.
func (node *commissioningNode) String() string {
	return node.Service.String()
}
