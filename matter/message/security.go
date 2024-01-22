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

package message

// 4.4.1.4. Security Flags (8 bits)
// SecurityFlag represents a message security flag.
type SecurityFlag uint8

// IsPrivacyMessage returns true if the message is privacy.
func (flag SecurityFlag) IsPrivacyMessage() bool {
	return (flag & 0x80) != 0
}

// IsControlledMessage returns true if the message is controlled.
func (flag SecurityFlag) IsControlledMessage() bool {
	return (flag & 0x40) != 0
}

// IsExtendedMessage returns true if the message is extended.
func (flag SecurityFlag) IsExtendedMessage() bool {
	return (flag & 0x20) != 0
}

// SessionType returns the session type.
func (flag SecurityFlag) SessionType() SessionType {
	return (SessionType)(flag & 0x03)
}
