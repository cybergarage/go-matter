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

import "github.com/cybergarage/go-safecast/safecast"

const (
	upper4BitsMask = 0x0F00
)

// Discriminator represents the discriminator value which specifies how to identify a device during commissioning.
type Discriminator uint16

// IsUpper4Bits returns true if the discriminator indicates only upper 4 bits are used for a manual pairing code.
func (d Discriminator) IsUpper4Bits() bool {
	return ((d & upper4BitsMask) == d)
}

// IsFull12Bits returns true if the discriminator indicates full 12 bits are used for a QR code.
func (d Discriminator) IsFull12Bits() bool {
	return !d.IsUpper4Bits()
}

// Equal returns true if the discriminator equals to the specified value.
func (d Discriminator) Equal(v any) bool {
	equal := func(v1, v2 uint16) bool {
		if v1 == v2 {
			return true
		}
		if (v1 & upper4BitsMask) == (v2 & upper4BitsMask) {
			return true
		}
		return false
	}
	switch v := v.(type) {
	case Discriminator:
		return equal(uint16(d), uint16(v))
	default:
		var uv uint16
		if err := safecast.ToUint16(v, &uv); err == nil {
			return equal(uint16(d), uv)
		}
	}
	return false
}
