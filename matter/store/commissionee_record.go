// Copyright (C) 2026 The go-matter Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package store

import "time"

// CommissioneeRecord is what a Commissioner keeps about one device it has
// successfully commissioned. CompressedFabricID+NodeID together match the
// mDNS operational-node service-instance name
// ("<compressedFabricID>-<nodeID>") a future reconnect-over-CASE feature
// would look the device up by.
type CommissioneeRecord struct {
	NodeID             uint64    `json:"nodeId"`
	FabricID           uint64    `json:"fabricId"`
	CompressedFabricID uint64    `json:"compressedFabricId"`
	VendorID           uint16    `json:"vendorId"`
	ProductID          uint16    `json:"productId"`
	Discriminator      uint16    `json:"discriminator,omitempty"`
	NOC                []byte    `json:"noc"`
	ICAC               []byte    `json:"icac,omitempty"`
	CommissionedAt     time.Time `json:"commissionedAt"`
}
