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

package matter

import "fmt"

type baseDevice struct {
}

func (d *baseDevice) String(dev CommissionableDevice) string {
	return fmt.Sprintf("VendorID: %d, ProductID: %d, Discriminator: %d",
		dev.VendorID(),
		dev.ProductID(),
		dev.Discriminator())
}

func (d *baseDevice) MarshalObject(dev CommissionableDevice) any {
	return struct {
		Discriminator uint16 `json:"discriminator"`
		VendorID      uint16 `json:"vendorId"`
		ProductID     uint16 `json:"productId"`
	}{
		Discriminator: uint16(dev.Discriminator()),
		VendorID:      uint16(dev.VendorID()),
		ProductID:     uint16(dev.ProductID()),
	}
}
