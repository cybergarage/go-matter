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
	"github.com/cybergarage/go-matter/matter/errors"
	"github.com/cybergarage/go-matter/matter/types"
)

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

func (scn *scanner) onScanResult(bleDev ble.Device) {
	bleSrv, ok := bleDev.LookupService(MatterServiceUUID)
	if !ok {
		return
	}
	dev, err := newDeviceWith(bleDev, bleSrv)
	if err != nil {
		return
	}
	scn.deviceMap.Store(dev.Address().String(), dev)
}

// Scan starts scanning for Bluetooth devices.
func (scn *scanner) Scan(ctx context.Context, opts ...ble.ScannerOption) error {
	scanHandler := ScanHandler(func(bleDev ble.Device) {
		scn.onScanResult(bleDev)
	})
	hasScanHandler := false
	for _, opt := range opts {
		if _, ok := opt.(ScanHandler); ok {
			hasScanHandler = true
			break
		}
	}
	if !hasScanHandler {
		opts = append(opts, scanHandler)
	}
	return scn.Scanner.Scan(ctx, opts...)
}

// DiscoveredDevices returns the list of discovered devices.
func (scn *scanner) DiscoveredDevices() []Device {
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

// LookupDeviceByDiscriminator looks up a scanned device by a discriminator.
func (scn *scanner) LookupDeviceByDiscriminator(v any) (Device, error) {
	lookupDisc, err := types.NewDiscriminatorFrom(v)
	if err != nil {
		return nil, err
	}

	var foundDev Device
	scn.deviceMap.Range(func(key, value any) bool {
		dev, ok := value.(Device)
		if !ok {
			return true
		}
		service, err := dev.Service()
		if err != nil {
			return true
		}
		devDisc := service.Discriminator()
		if lookupDisc.Equal(devDisc) {
			foundDev = dev
			return false
		}
		return true
	})

	if foundDev == nil {
		return nil, errors.ErrNotFound
	}

	return foundDev, nil
}
