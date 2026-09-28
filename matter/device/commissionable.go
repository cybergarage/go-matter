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

package device

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/cybergarage/go-matter/matter/crypto"
	"github.com/cybergarage/go-matter/matter/mdns"
)

// DNS-SD names of a commissionable node (Matter Core 4.3.1).
const (
	CommissionableServiceType = "_matterc._udp"
	ServiceDomain             = "local"
	subtypeLabel              = "_sub"
)

// Limits of the commissionable TXT values (Matter Core 4.3.1, 4.3.4).
const (
	MaxDiscriminator            = 0x0FFF
	MaxDeviceNameLength         = 32
	MaxPairingInstructionLength = 128
	MaxSessionInterval          = 3600000
)

// CommissionableService describes the _matterc._udp service a device
// advertises while its commissioning window is open (Matter Core 4.3.1). It
// is backend-neutral: an Advertiser turns it into mDNS records.
type CommissionableService struct {
	// InstanceName is the DNS-SD instance name: 64 random bits as 16
	// uppercase hex digits, chosen anew each time the window opens.
	InstanceName string
	// Hostname is the target host's name without the domain: 16 uppercase
	// hex digits (4.3.1.1).
	Hostname string
	// Port is the UDP port the device receives Matter messages on.
	Port int

	Discriminator     uint16
	VendorID          uint16
	ProductID         uint16
	CommissioningMode mdns.CommissioningMode
	// DeviceType is the primary device type; 0 omits it.
	DeviceType uint32
	// DeviceName is a user-visible name of up to 32 bytes; empty omits it.
	DeviceName string
	// PairingHint and PairingInstruction tell a user how to put the device
	// into commissioning mode; zero values omit them.
	PairingHint        uint16
	PairingInstruction string
	// SessionIdleInterval, SessionActiveInterval and
	// SessionActiveThreshold are the MRP parameters in milliseconds
	// (4.3.4); 0 omits them and the defaults apply.
	SessionIdleInterval    uint32
	SessionActiveInterval  uint32
	SessionActiveThreshold uint16
}

// NewInstanceName returns a random commissionable instance name.
func NewInstanceName() string {
	return randomHexName()
}

// NewHostname returns a random host name in the form Matter expects.
func NewHostname() string {
	return randomHexName()
}

func randomHexName() string {
	return strings.ToUpper(fmt.Sprintf("%016x", crypto.CryptoDRBG(8)))
}

// Validate reports whether s can be advertised.
func (s CommissionableService) Validate() error {
	if !mdns.HostnameRegexp.MatchString(s.InstanceName) {
		return fmt.Errorf("device: instance name %q is not 16 uppercase hex digits", s.InstanceName)
	}
	if !mdns.HostnameRegexp.MatchString(s.Hostname) {
		return fmt.Errorf("device: host name %q is not 16 uppercase hex digits", s.Hostname)
	}
	if s.Port <= 0 || s.Port > 0xFFFF {
		return fmt.Errorf("device: port %d out of range", s.Port)
	}
	if s.Discriminator > MaxDiscriminator {
		return fmt.Errorf("device: discriminator 0x%X exceeds 12 bits", s.Discriminator)
	}
	if len(s.DeviceName) > MaxDeviceNameLength {
		return fmt.Errorf("device: device name is %d bytes, max %d", len(s.DeviceName), MaxDeviceNameLength)
	}
	if len(s.PairingInstruction) > MaxPairingInstructionLength {
		return fmt.Errorf("device: pairing instruction is %d bytes, max %d", len(s.PairingInstruction), MaxPairingInstructionLength)
	}
	if s.SessionIdleInterval > MaxSessionInterval || s.SessionActiveInterval > MaxSessionInterval {
		return fmt.Errorf("device: session interval exceeds %d ms", MaxSessionInterval)
	}
	return nil
}

// ServiceName returns the fully qualified service type,
// "_matterc._udp.local".
func (s CommissionableService) ServiceName() string {
	return CommissionableServiceType + "." + ServiceDomain
}

// InstanceFullName returns the fully qualified instance name, such as
// "665F6E75B5D3A9C2._matterc._udp.local".
func (s CommissionableService) InstanceFullName() string {
	return s.InstanceName + "." + s.ServiceName()
}

// HostFullName returns the fully qualified host name the SRV record points
// to, such as "B75AFB458ECD6D6F.local".
func (s CommissionableService) HostFullName() string {
	return s.Hostname + "." + ServiceDomain
}

// Subtypes returns the commissioning subtype labels (4.3.1.3), such as
// "_L3840", "_S15", "_V65521", "_CM" and "_T257". Values are decimal
// without leading zeros. _CM is present only while CommissioningMode is not
// 0, and _T only when DeviceType is set.
func (s CommissionableService) Subtypes() []string {
	subtypes := []string{
		mdns.SubtypeDiscriminatorLong + strconv.Itoa(int(s.Discriminator)),
		mdns.SubtypeDiscriminatorShort + strconv.Itoa(int(s.Discriminator>>8)),
	}
	if s.VendorID != 0 {
		subtypes = append(subtypes, mdns.SubtypeVendorID+strconv.Itoa(int(s.VendorID)))
	}
	if s.DeviceType != 0 {
		subtypes = append(subtypes, mdns.SubtypeDeviceType+strconv.FormatUint(uint64(s.DeviceType), 10))
	}
	if s.CommissioningMode != mdns.CommissioningModeAbsence {
		subtypes = append(subtypes, mdns.SubtypeCommissioningMode)
	}
	return subtypes
}

// SubtypeFullNames returns each subtype as the name a browser queries, such
// as "_L3840._sub._matterc._udp.local".
func (s CommissionableService) SubtypeFullNames() []string {
	subtypes := s.Subtypes()
	names := make([]string, 0, len(subtypes))
	for _, st := range subtypes {
		names = append(names, st+"."+subtypeLabel+"."+s.ServiceName())
	}
	return names
}

// TXT returns the TXT record entries as "key=value" strings (4.3.1.4 to
// 4.3.1.12, 4.3.4), in a fixed order.
func (s CommissionableService) TXT() []string {
	txt := []string{
		txtEntry(mdns.TxtRecordDiscriminator, strconv.Itoa(int(s.Discriminator))),
		txtEntry(mdns.TxtRecordCommissioningMode, s.CommissioningMode.String()),
	}
	if s.VendorID != 0 {
		vp := strconv.Itoa(int(s.VendorID))
		if s.ProductID != 0 {
			vp += "+" + strconv.Itoa(int(s.ProductID))
		}
		txt = append(txt, txtEntry(mdns.TxtRecordVendorProductID, vp))
	}
	if s.DeviceType != 0 {
		txt = append(txt, txtEntry(mdns.TxtRecordDeviceType, strconv.FormatUint(uint64(s.DeviceType), 10)))
	}
	if s.DeviceName != "" {
		txt = append(txt, txtEntry(mdns.TxtRecordDeviceName, s.DeviceName))
	}
	if s.SessionIdleInterval != 0 {
		txt = append(txt, txtEntry(TxtRecordSessionIdleInterval, strconv.FormatUint(uint64(s.SessionIdleInterval), 10)))
	}
	if s.SessionActiveInterval != 0 {
		txt = append(txt, txtEntry(TxtRecordSessionActiveInterval, strconv.FormatUint(uint64(s.SessionActiveInterval), 10)))
	}
	if s.SessionActiveThreshold != 0 {
		txt = append(txt, txtEntry(TxtRecordSessionActiveThreshold, strconv.Itoa(int(s.SessionActiveThreshold))))
	}
	if s.PairingHint != 0 {
		txt = append(txt, txtEntry(mdns.TxtRecordPairingHint, strconv.Itoa(int(s.PairingHint))))
	}
	if s.PairingInstruction != "" {
		txt = append(txt, txtEntry(mdns.TxtRecordPairingInstruction, s.PairingInstruction))
	}
	return txt
}

// TXT keys common to every Matter service (Matter Core 4.3.4).
const (
	TxtRecordSessionIdleInterval    = "SII"
	TxtRecordSessionActiveInterval  = "SAI"
	TxtRecordSessionActiveThreshold = "SAT"
)

func txtEntry(key, value string) string {
	return key + "=" + value
}
