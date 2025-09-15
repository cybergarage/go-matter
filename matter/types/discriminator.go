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

package types

// Discriminator represents the discriminator value which specifies how to identify a device during commissioning.
type Discriminator uint16

// IsUpper4Bits returns true if the discriminator indicates only upper 4 bits are used for a manual pairing code.
func (d Discriminator) IsUpper4Bits() bool {
	return ((d & 0x0F00) == d)
}

// IsFull12Bits returns true if the discriminator indicates full 12 bits are used for a QR code.
func (d Discriminator) IsFull12Bits() bool {
	return !d.IsUpper4Bits()
}
