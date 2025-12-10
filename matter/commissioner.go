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
	"time"

	"github.com/cybergarage/go-matter/matter/ble"
	"github.com/cybergarage/go-matter/matter/encoding"
	"github.com/cybergarage/go-matter/matter/mdns"
)

const (
	// DefaultCommissioningTimeout is the default commissioning timeout.
	DefaultCommissioningTimeout = time.Duration(5 * time.Second)
)

// CommissioningOptions represents the commissioning options.
type CommissioningOptions interface {
	encoding.OnboardingPayload
}

// Commissioner represents a commissioner interface.
type Commissioner interface {
	// Scannar returns the BLE scanner.
	Scannar() ble.Scanner
	// Discoverer returns the mDNS discoverer.
	Discoverer() mdns.Discoverer
	// Commission commissions a device with the given commissioning options.
	Commission(ctx context.Context, options CommissioningOptions) error
	// Start starts the commissioner.
	Start() error
	// Stop stops the commissioner.
	Stop() error
}
