// Copyright (C) 2025 The go-matter Authors. All rights reserved.
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

import (
	"github.com/cybergarage/go-matter/matter/types"
)

// VendorID represents a vendor ID.
// 2.5.2. Vendor Identifier (Vendor ID, VID).
type VendorID = types.VendorID

// ProductID represents a product ID.
// 2.5.3. Product Identifier (Product ID, PID).
type ProductID = types.ProductID

// Header represents the protocol layer header.
// 4.4.3. Protocol Header Field Descriptions.
type Header interface {
	// ExchangeFlags returns the exchange flags.
	ExchangeFlags() ExchangeFlag
	// Opcode returns the opcode.
	Opcode() uint8
	// ExchangeID returns the exchange ID.
	ExchangeID() ExchangeID
	// ProtocolID returns the protocol ID.
	ProtocolID() ProtocolID
	// VendorID returns the vendor ID if present.
	VendorID() (VendorID, bool)
	// AckCounter returns the acknowledgement counter if present.
	AckCounter() (uint32, bool)
	// SecuredExtensions returns the secured extensions bytes if present.
	SecuredExtensions() ([]byte, bool)
	// IsInitiator returns true if the initiator flag is set.
	IsInitiator() bool
	// IsAcknowledgement returns true if the acknowledgement flag is set.
	IsAcknowledgement() bool
	// IsReliability returns true if the reliability requested flag is set.
	IsReliability() bool
	// HasSecuredExtensions returns true if the secured extensions flag is set.
	HasSecuredExtensions() bool
	// HasVendorID returns true if the vendor ID flag is set.
	HasVendorID() bool
	// Bytes encodes the header into a byte slice for transmission.
	Bytes() []byte
	// String returns a human-readable representation of the header for debugging purposes.
	String() string
}
