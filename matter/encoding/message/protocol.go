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

package message

import (
	"fmt"
)

// ProtocolID represents a protocol ID.
// 4.4.3.4. Protocol ID (16 bits).
type ProtocolID uint16

const (
	SecureChannel             ProtocolID = 0x0000
	InteractionModel          ProtocolID = 0x0001
	BDX                       ProtocolID = 0x0002
	UserDirectedCommissioning ProtocolID = 0x0003
	Testing                   ProtocolID = 0x0004
)

// IsSecureChannel returns true if the protocol ID is for Secure Channel.
func (p ProtocolID) IsSecureChannel() bool {
	return p == SecureChannel
}

// IsInteractionModel returns true if the protocol ID is for Interaction Model.
func (p ProtocolID) IsInteractionModel() bool {
	return p == InteractionModel
}

// IsBDX returns true if the protocol ID is for BDX.
func (p ProtocolID) IsBDX() bool {
	return p == BDX
}

// IsUserDirectedCommissioning returns true if the protocol ID is for User Directed Commissioning.
func (p ProtocolID) IsUserDirectedCommissioning() bool {
	return p == UserDirectedCommissioning
}

// IsTesting returns true if the protocol ID is for Testing.
func (p ProtocolID) IsTesting() bool {
	return p == Testing
}

// String returns a human-readable string representation of the ProtocolID.
func (p ProtocolID) String() string {
	switch p {
	case SecureChannel:
		return "SecureChannel"
	case InteractionModel:
		return "InteractionModel"
	case BDX:
		return "BDX"
	case UserDirectedCommissioning:
		return "UserDirectedCommissioning"
	case Testing:
		return "Testing"
	default:
		return fmt.Sprintf("Unknown(0x%04X)", uint16(p))
	}
}
