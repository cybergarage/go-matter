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

const (
	// CommissionableNodeService represents the mDNS service type for commissionable nodes.
	// 4.3.1. Commissionable Node Discovery.
	CommissionableNodeService = "_matterc._udp"
	// Commissioner Discovery Service represents the mDNS service type for commissioners.
	// 4.3.3. Commissioner Discovery
	CommissionerDiscoveryService = "_matterd._udp"
	// OperationalNodeService represents the mDNS service type for operational nodes.
	// 4.3.2.3. Operational Service Type.
	OperationalNodeService = "_matter._tcp"
)

// 4.3.1.3. Commissioning Subtypes.
const (
	// QuerySubtypeLongDiscriminator represents the long discriminator query subtype.
	QuerySubtypeLongDiscriminator = "_L"
	// QuerySubtypeShortDiscriminator represents the short discriminator query subtype.
	QuerySubtypeShortDiscriminator = "_S"
	// QuerySubtypeVendorID represents the vendor ID query subtype.
	QuerySubtypeVendorID = "_V"
	// QuerySubtypeDeviceType represents the device type query subtype.
	QuerySubtypeDeviceType = "_T"
	// QuerySubtypeCommissioningMode represents the commissioning mode query subtype.
	QuerySubtypeCommissioningMode = "_CM"
)

// Query represents a mDNS query.
type Query interface {
	// Subtype returns the subtype for the query.
	Subtype() string
	// Service returns the service for the query.
	Service() string
	// DomainName returns the domain name for the query.
	DomainName() string
	// String returns the string representation of the query.
	String() string
}
