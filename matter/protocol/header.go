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

// 4.4.3. Protocol Header Field Descriptions
// Header represents the protocol layer header.
type Header interface {
	// ExchangeFlags returns the exchange flags.
	ExchangeFlags() uint8
	// Opcode returns the opcode.
	Opcode() uint8
	// ExchangeID returns the exchange ID.
	ExchangeID() uint16
	// ProtocolID returns the protocol ID.
	ProtocolID() uint16
	// VendorID returns the vendor ID.
	VendorID() uint16
	// AckCounter returns the acknowledgement counter.
	AckCounter() uint32
	// IsInitiator returns true if the initiator flag is set.
	IsInitiator() bool
	// IsAck returns true if the acknowledgement flag is set.
	IsAck() bool
	// IsReliabilityRequested returns true if the reliability requested flag is set.
	IsReliabilityRequested() bool
	// HasSecuredExtensions returns true if the secured extensions flag is set.
	HasSecuredExtensions() bool
	// HasVendorID returns true if the vendor ID flag is set.
	HasVendorID() bool
	// Bytes encodes the header into a byte slice for transmission.
	Bytes() []byte
	// String returns a human-readable representation of the header for debugging purposes.
	String() string
}
