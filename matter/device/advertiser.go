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

package device

// Advertiser publishes a device's DNS-SD services on the network.
//
// A Device publishes through an MDNSAdvertiser, the go-mdns responder,
// unless WithAdvertiser gives it another one, such as a wrapper of the
// platform's service (Bonjour, Avahi), or nil to advertise nothing.
// CommissionableService provides the names, subtypes and TXT entries an
// implementation needs.
type Advertiser interface {
	// AdvertiseCommissionable publishes svc, replacing whatever this
	// Advertiser published for the device before.
	AdvertiseCommissionable(svc CommissionableService) error
	// Withdraw stops publishing the device's services.
	Withdraw() error
}
