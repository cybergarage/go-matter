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

import (
	"fmt"

	"github.com/cybergarage/go-safecast/safecast"
)

// VendorID represents a vendor ID.
// 2.5.2. Vendor Identifier (Vendor ID, VID).
type VendorID uint16

// NewVendorIDFrom creates a new VendorID from the given value.
func NewVendorIDFrom(v any) (VendorID, error) {
	var vid uint16
	if err := safecast.ToUint16(v, &vid); err != nil {
		return 0, err
	}
	return VendorID(vid), nil
}

// Equal returns true if the VendorID is equal to the given VendorID.
func (vid VendorID) Equal(other VendorID) bool {
	if vid == 0 || other == 0 {
		return true
	}
	return vid == other
}

// String returns the string representation of the VendorID.
func (vid VendorID) String() string {
	return fmt.Sprintf("%d", uint(vid))
}
