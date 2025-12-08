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
	_ "embed"
	"strings"

	"github.com/cybergarage/go-mdns/mdns"
	"github.com/cybergarage/go-mdns/mdns/dns"
)

// commissionee represents a commissionee.
type commissionee struct {
	mdns.Service
}

// NewCommissioneeWithMessage returns a new commissionee with a mDNS message.
func NewCommissioneeWithMessage(msg dns.Message) (Commissionee, error) {
	service, err := mdns.NewService(
		mdns.WithServiceMessage(msg),
	)
	if err != nil {
		return nil, err
	}
	return NewCommissioneeWithService(service), nil
}

// NewCommissioneeWithService returns a new commissionee with a mDNS service.
func NewCommissioneeWithService(service mdns.Service) Commissionee {
	com := &commissionee{
		Service: service,
	}
	return com
}

// LookupSubtype returns a subtype for the specified prefix.
func (com *commissionee) LookupSubtype(prefix string) (string, bool) {
	record, ok := com.Service.LookupResourceByNamePrefix(prefix)
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
func (com *commissionee) LookupTxtAttribute(name string) (string, bool) {
	attr, ok := com.Service.LookupResourceAttribute(name)
	if !ok {
		return "", false
	}
	return attr.Value(), true
}

func (com *commissionee) appendLookupSubtype(records []string, name string) []string {
	v, ok := com.LookupSubtype(name)
	if !ok {
		return records
	}
	return append(records, v)
}

func (com *commissionee) appendLookupTxtAttribute(records []string, name string) []string {
	v, ok := com.LookupTxtAttribute(name)
	if !ok {
		return records
	}
	return append(records, v)
}

// LookupDiscriminator returns a full discriminator or short discriminator.
// 4.3.1.5. TXT key for discriminator (D).
func (com *commissionee) LookupDiscriminator() (string, bool) {
	d, ok := com.LookupFullDiscriminator()
	if ok {
		return d, true
	}
	return com.LookupShortDiscriminator()
}

// LookupFullDiscriminator returns a full 12-bit discriminator.
// 4.3.1.3. Commissioning Subtypes (_L).
func (com *commissionee) LookupFullDiscriminator() (string, bool) {
	d, ok := com.LookupTxtAttribute(TxtRecordDiscriminator)
	if ok {
		return d, true
	}
	d, ok = com.LookupSubtype(SubtypeDiscriminatorLong)
	if ok {
		return d, true
	}
	return com.LookupSubtype(SubtypeDiscriminatorShort)
}

// LookupShortDiscriminator returns a short 4-bit discriminator.
// 4.3.1.3. Commissioning Subtypes (_S).
func (com *commissionee) LookupShortDiscriminator() (string, bool) {
	return com.LookupSubtype(SubtypeDiscriminatorShort)
}

// LookupVendorID returns a vendor and product ID.
// 4.3.1.3. Commissioning Subtypes (_V)
// 4.3.1.6. TXT key for Vendor ID and Product ID (VP).
func (com *commissionee) LookupVendorID() (string, bool) {
	venderID, _, ok := com.LookupVendorProductID()
	if ok {
		return venderID, true
	}
	return com.LookupSubtype(SubtypeVendorID)
}

// LookupVendorProductID returns a vendor and product ID.
// 4.3.1.6. TXT key for Vendor ID and Product ID (VP).
func (com *commissionee) LookupVendorProductID() (string, string, bool) {
	splitVenderProductID := func(vp string) (string, string, bool) {
		vpList := strings.Split(vp, "+")
		if len(vpList) < 1 {
			return vpList[0], "", true
		}
		return vpList[0], vpList[1], true
	}

	vp, ok := com.LookupTxtAttribute(TxtRecordVendorProductID)
	if !ok || len(vp) == 0 {
		return "", "", false
	}

	return splitVenderProductID(vp)
}

// LookupCommissioningMode returns a commissioning mode.
// 4.3.1.3. Commissioning Subtypes (_CM)
// 4.3.1.7. TXT key for commissioning mode (CM).
func (com *commissionee) LookupCommissioningMode() (string, bool) {
	cmFrom := func(cms string) (string, bool) {
		if len(cms) == 0 {
			return CommissioningModeNone, true
		}
		return cms, true
	}

	var records []string
	records = com.appendLookupTxtAttribute(records, TxtRecordCommissioningMode)
	records = com.appendLookupSubtype(records, SubtypeCommissioningMode)

	for _, cms := range records {
		cm, ok := cmFrom(cms)
		if ok {
			return cm, true
		}
	}

	return CommissioningModeNone, false
}

// LookupDeviceType returns a device type.
// 4.3.1.3. Commissioning Subtypes (_T)
// 4.3.1.8. TXT key for device type (DT).
func (com *commissionee) LookupDeviceType() (DeviceType, bool) {
	deviceTypeFrom := func(dts string) (DeviceType, bool) {
		dt, err := NewDeviceTypeFromString(dts)
		if err != nil {
			return DeviceTypeUnknown, false
		}
		return dt, true
	}

	var records []string
	records = com.appendLookupTxtAttribute(records, TxtRecordDeviceType)
	records = com.appendLookupSubtype(records, SubtypeDeviceType)

	for _, dts := range records {
		dt, ok := deviceTypeFrom(dts)
		if ok {
			return dt, true
		}
	}

	return DeviceTypeUnknown, false
}

// LookupDeviceName returns a device name.
// 4.3.1.9. TXT key for device name (DN).
func (com *commissionee) LookupDeviceName() (string, bool) {
	return com.LookupTxtAttribute(TxtRecordDeviceName)
}

// LookupRotatingDeviceID returns a rotating device identifier.
// 4.3.1.10. TXT key for rotating device identifier (RI).
func (com *commissionee) LookupRotatingDeviceID() (string, bool) {
	return com.LookupTxtAttribute(TxtRecordRotatingDeviceID)
}

// LookupPairingHint returns a pairing hint.
// 4.3.1.11. TXT key for pairing hint (PH).
func (com *commissionee) LookupPairingHint() (PairingHint, bool) {
	phs, ok := com.LookupTxtAttribute(TxtRecordPairingHint)
	if !ok {
		return PairingHintNone, false
	}
	ph, err := NewPairingHintFromString(phs)
	if err != nil {
		return PairingHintNone, false
	}
	return ph, true
}

// LookupPairingInstructions returns a pairing instructions.
// 4.3.1.12. TXT key for pairing instructions (PI).
func (com *commissionee) LookupPairingInstructions() (string, bool) {
	return com.LookupTxtAttribute(TxtRecordPairingInstruction)
}
