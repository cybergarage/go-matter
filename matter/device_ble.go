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

import (
	"context"

	"github.com/cybergarage/go-matter/matter/ble"
)

type bleDevice struct {
	ble.Service
}

func newBLEDevice(service ble.Service) CommissionableDevice {
	return &bleDevice{
		Service: service,
	}
}

// Commission commissions the node with the given commissioning options.
func (d *bleDevice) Commission(ctx context.Context, payload OnboardingPayload) error {
	return nil
}
