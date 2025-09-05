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
	"sync"

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
	deviceMap sync.Map
}

// NewScanner returns a new BLE scanner.
func NewScanner() Scanner {
	return &scanner{
		Scanner:   ble.NewScanner(),
		deviceMap: sync.Map{},
	}
}

// Devices returns the list of discovered devices.
func (scn *scanner) Devices() []Device {
	var devices []Device
	scn.deviceMap.Range(func(key, value any) bool {
		device, ok := value.(Device)
		if ok {
			devices = append(devices, device)
		}
		return true
	})
	return devices
}

func (scn *scanner) onScanResult(bleDev ble.Device) {
	bleSrv, ok := bleDev.LookupService(MatterServiceUUID)
	if !ok {
		return
	}
	dev, err := newDeviceWith(bleDev, bleSrv)
	if err != nil {
		return
	}
	scn.deviceMap.Store(dev.Address(), dev)
}

// Scan starts scanning for Bluetooth devices.
func (scn *scanner) Scan(ctx context.Context) error {
	onScanResultlistener := ble.OnScanResult(func(bleDev ble.Device) {
		scn.onScanResult(bleDev)
	})
	return scn.Scanner.Scan(ctx, onScanResultlistener)
}
