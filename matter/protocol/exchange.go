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

package protocol

// ExchangeID represents a exchange ID.
// 4.4.3. Protocol Header Field Descriptions
// 4.4.3.3. Exchange ID (16 bits).
type ExchangeID uint16

// ExchangeFlag represents a exchange flag.
// 4.4.3. Protocol Header Field Descriptions
// 4.4.3.1. Exchange Flags (8 bits).
type ExchangeFlag uint8

const (
	// ExchangeFlagInitiator (I) indicates the sender is the initiator (bit 0).
	ExchangeFlagInitiator = 0x01
	// ExchangeFlagAck (A) indicates this is an acknowledgement (bit 1).
	ExchangeFlagAck = 0x02
	// ExchangeFlagReliability (R) indicates reliable transmission is requested (bit 2).
	ExchangeFlagReliability = 0x04
	// ExchangeFlagSecuredExtensions (SX) indicates secured extensions are present (bit 3).
	ExchangeFlagSecuredExtensions = 0x08
	// ExchangeFlagVendor (V) indicates a vendor-specific protocol (bit 4).
	ExchangeFlagVendor = 0x10
)

// IsInitiator returns true if the flag is initiator.
func (flag ExchangeFlag) IsInitiator() bool {
	return (flag & ExchangeFlagInitiator) != 0
}

// IsAcknowledgement returns true if the flag is acknowledgement.
func (flag ExchangeFlag) IsAcknowledgement() bool {
	return (flag & ExchangeFlagAck) != 0
}

// IsReliability returns true if the flag is reliability.
func (flag ExchangeFlag) IsReliability() bool {
	return (flag & ExchangeFlagReliability) != 0
}

// IsSecuredExtension returns true if the flag is secured extension.
func (flag ExchangeFlag) IsSecuredExtension() bool {
	return (flag & ExchangeFlagSecuredExtensions) != 0
}

// IsVendor returns true if the flag is vendor.
func (flag ExchangeFlag) IsVendor() bool {
	return (flag & ExchangeFlagVendor) != 0
}
