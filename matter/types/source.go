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

// DiscoverySource represents a discovery source.
type DiscoverySource int

const (
	// DiscoverySourceMDNS represents the mDNS discovery source.
	DiscoverySourceMDNS DiscoverySource = iota + 1
	// DiscoverySourceBLE represents the BLE discovery source.
	DiscoverySourceBLE
)

// String returns the string representation of the discovery source.
func (ds DiscoverySource) String() string {
	switch ds {
	case DiscoverySourceMDNS:
		return "mDNS"
	case DiscoverySourceBLE:
		return "BLE"
	default:
		return "Unknown"
	}
}
