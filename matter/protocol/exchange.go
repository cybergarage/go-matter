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

// ExchangeFlag represents a exchange flag.
type ExchangeFlag uint8

// ExchangeID represents a exchange ID.
type ExchangeID uint16

// IsInitiator returns true if the flag is initiator.
func (flag ExchangeFlag) IsInitiator() bool {
	return (flag & 0x01) != 0
}

// IsAcknowledgement returns true if the flag is acknowledgement.
func (flag ExchangeFlag) IsAcknowledgement() bool {
	return (flag & 0x20) != 0
}

// IsReliability returns true if the flag is reliability.
func (flag ExchangeFlag) IsReliability() bool {
	return (flag & 0x40) != 0
}

// IsSecuredExtension returns true if the flag is secured extension.
func (flag ExchangeFlag) IsSecuredExtension() bool {
	return (flag & 0x80) != 0
}

// IsVendor returns true if the flag is vendor.
func (flag ExchangeFlag) IsVendor() bool {
	return (flag & 0x10) != 0
}
