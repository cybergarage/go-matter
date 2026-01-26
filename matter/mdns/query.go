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
	"github.com/cybergarage/go-mdns/mdns"
)

const (
	// 4.3.1. Commissionable Node Discovery.
	// CommissionableNodeService represents the mDNS service type for commissionable nodes.
	CommissionableNodeService = "_matterc._udp"
	// 4.3.3. Commissioner Discovery.
	// Commissioner Discovery Service represents the mDNS service type for commissioners.
	CommissionerDiscoveryService = "_matterd._udp"
	// 4.3.2.3. Operational Service Type.
	// OperationalNodeService represents the mDNS service type for operational nodes.
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

// Message represents a mDNS message.
type Message = mdns.Message

// MessageHandler represents a mDNS message handler.
type MessageHandler = mdns.MessageHandler

// Query represents a mDNS query.
type Query interface {
	// Subtype returns the subtype for the query.
	Subtype() string
	// Service returns the service for the query.
	Service() string
	// DomainName returns the domain name for the query.
	DomainName() string
	// MessageHandler returns the message handler for the query if set.
	MessageHandler() (MessageHandler, bool)
	// String returns the string representation of the query.
	String() string
}
