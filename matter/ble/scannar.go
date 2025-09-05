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

package ble

import (
	"context"

	"github.com/cybergarage/go-ble/ble"
)

// Scanner represents a BLE scanner.
type Scanner interface {
	// Devices returns the list of discovered devices.
	Devices() []Device
	// Scan starts scanning for Bluetooth devices.
	Scan(ctx context.Context) error
}

type scanner struct {
	ble.Scanner
	devices []Device
}

// NewScanner returns a new BLE scanner.
func NewScanner() Scanner {
	return &scanner{
		Scanner: ble.NewScanner(),
		devices: []Device{},
	}
}

// Devices returns the list of discovered devices.
func (scn *scanner) Devices() []Device {
	return scn.devices
}

func (scn *scanner) onScanResult(bleDev ble.Device) {
	if _, ok := bleDev.LookupService(MatterServiceUUID); !ok {
		return
	}
	dev, err := NewDeviceWith(bleDev)
	if err != nil {
		return
	}
	scn.devices = append(scn.devices, dev)
}

// Scan starts scanning for Bluetooth devices.
func (scn *scanner) Scan(ctx context.Context) error {
	onScanResultlistener := ble.OnScanResult(func(bleDev ble.Device) {
		scn.onScanResult(bleDev)
	})
	return scn.Scanner.Scan(ctx, onScanResultlistener)
}
