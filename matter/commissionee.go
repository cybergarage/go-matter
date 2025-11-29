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

package matter

import (
	_ "embed"
	"strings"

	"github.com/cybergarage/go-mdns/mdns"
	"github.com/cybergarage/go-mdns/mdns/dns"
)

// Commissionee represents a commissionee.
type Commissionee struct {
	mdns.Service
}

// NewCommissioneeWithMessage returns a new commissionee with a mDNS message.
func NewCommissioneeWithMessage(msg *dns.Message) (*Commissionee, error) {
	service, err := mdns.NewService(
		mdns.WithServiceMessage(msg),
	)
	if err != nil {
		return nil, err
	}
	return NewCommissioneeWithService(service), nil
}

// NewCommissioneeWithService returns a new commissionee with a mDNS service.
func NewCommissioneeWithService(service mdns.Service) *Commissionee {
	com := &Commissionee{
		Service: service,
	}
	return com
}

// LookupSubtype returns a subtype for the specified prefix.
func (com *Commissionee) LookupSubtype(prefix string) (string, bool) {
	record, ok := com.Service.LookupResourceRecordByNamePrefix(prefix)
	if !ok {
		return "", false
	}
	names := strings.Split(record.Name(), ".")
	if len(names) < 1 {
		return "", false
	}
	return names[0][len(prefix):], true
}

// LookupAttribute returns an attribute value for the specified name.
func (com *Commissionee) LookupAttribute(name string) (string, bool) {
	attr, ok := com.Service.LookupAttribute(name)
	if !ok {
		return "", false
	}
	return attr.Value(), true
}

func (com *Commissionee) appendLookupSubtype(records []string, name string) []string {
	v, ok := com.LookupSubtype(name)
	if !ok {
		return records
	}
	return append(records, v)
}

func (com *Commissionee) appendLookupAttribute(records []string, name string) []string {
	v, ok := com.LookupAttribute(name)
	if !ok {
		return records
	}
	return append(records, v)
}

// 4.3.1.3. Commissioning Subtypes (_L,_S)
// 4.3.1.5. TXT key for discriminator (D)
// LookupDiscriminator returns a discriminator.
func (com *Commissionee) LookupDiscriminator() (string, bool) {
	d, ok := com.LookupFullDiscriminator()
	if ok {
		return d, true
	}
	return com.LookupShortDiscriminator()
}

// 4.3.1.3. Commissioning Subtypes (_L)
// LookupDiscriminator returns a full 12-bit discriminator.
func (com *Commissionee) LookupFullDiscriminator() (string, bool) {
	d, ok := com.LookupAttribute(TxtRecordDiscriminator)
	if ok {
		return d, true
	}
	d, ok = com.LookupSubtype(SubtypeDiscriminatorLong)
	if ok {
		return d, true
	}
	return com.LookupSubtype(SubtypeDiscriminatorShort)
}

// 4.3.1.3. Commissioning Subtypes (_S)
// LookupShortDiscriminator returns a short 4-bit discriminator.
func (com *Commissionee) LookupShortDiscriminator() (string, bool) {
	return com.LookupSubtype(SubtypeDiscriminatorShort)
}

// 4.3.1.3. Commissioning Subtypes (_V)
// 4.3.1.6. TXT key for Vendor ID and Product ID (VP)
// LookupVendorID returns a vendor and product ID.
func (com *Commissionee) LookupVendorID() (string, bool) {
	venderID, _, ok := com.LookupVendorProductID()
	if ok {
		return venderID, true
	}
	return com.LookupSubtype(SubtypeVendorID)
}

// 4.3.1.6. TXT key for Vendor ID and Product ID (VP)
// LookupVendorProductID returns a vendor and product ID.
func (com *Commissionee) LookupVendorProductID() (string, string, bool) {
	splitVenderProductID := func(vp string) (string, string, bool) {
		vpList := strings.Split(vp, "+")
		if len(vpList) < 1 {
			return vpList[0], "", true
		}
		return vpList[0], vpList[1], true
	}

	vp, ok := com.LookupAttribute(TxtRecordVendorProductID)
	if !ok || len(vp) == 0 {
		return "", "", false
	}

	return splitVenderProductID(vp)
}

// 4.3.1.3. Commissioning Subtypes (_CM)
// 4.3.1.7. TXT key for commissioning mode (CM)
// LookupCommissioningMode returns a commissioning mode.
func (com *Commissionee) LookupCommissioningMode() (string, bool) {
	cmFrom := func(cms string) (string, bool) {
		if len(cms) == 0 {
			return CommissioningModeNone, true
		}
		return cms, true
	}

	var records []string
	records = com.appendLookupAttribute(records, TxtRecordCommissioningMode)
	records = com.appendLookupSubtype(records, SubtypeCommissioningMode)

	for _, cms := range records {
		cm, ok := cmFrom(cms)
		if ok {
			return cm, true
		}
	}

	return CommissioningModeNone, false
}

// 4.3.1.3. Commissioning Subtypes (_T)
// 4.3.1.8. TXT key for device type (DT)
// LookupDeviceType returns a device type.
func (com *Commissionee) LookupDeviceType() (DeviceType, bool) {
	deviceTypeFrom := func(dts string) (DeviceType, bool) {
		dt, err := NewDeviceTypeFromString(dts)
		if err != nil {
			return DeviceTypeUnknown, false
		}
		return dt, true
	}

	var records []string
	records = com.appendLookupAttribute(records, TxtRecordDeviceType)
	records = com.appendLookupSubtype(records, SubtypeDeviceType)

	for _, dts := range records {
		dt, ok := deviceTypeFrom(dts)
		if ok {
			return dt, true
		}
	}

	return DeviceTypeUnknown, false
}

// 4.3.1.9. TXT key for device name (DN)
// LookupDeviceName returns a device name.
func (com *Commissionee) LookupDeviceName() (string, bool) {
	return com.LookupAttribute(TxtRecordDeviceName)
}

// 4.3.1.10. TXT key for rotating device identifier (RI)
// LookupRotatingDeviceID returns a rotating device identifier.
func (com *Commissionee) LookupRotatingDeviceID() (string, bool) {
	return com.LookupAttribute(TxtRecordRotatingDeviceID)
}

// 4.3.1.11. TXT key for pairing hint (PH)
// LookupPairingHint returns a pairing hint.
func (com *Commissionee) LookupPairingHint() (PairingHint, bool) {
	phs, ok := com.LookupAttribute(TxtRecordPairingHint)
	if !ok {
		return PairingHintNone, false
	}
	ph, err := NewPairingHintFromString(phs)
	if err != nil {
		return PairingHintNone, false
	}
	return ph, true
}

// 4.3.1.12. TXT key for pairing instructions (PI)
// LookupPairingInstructions returns a pairing instructions.
func (com *Commissionee) LookupPairingInstructions() (string, bool) {
	return com.LookupAttribute(TxtRecordPairingInstruction)
}
