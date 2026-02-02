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
	"fmt"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter/ble"
	"github.com/cybergarage/go-matter/matter/types"
)

type bleDevice struct {
	*baseDevice
	ble.Device
	ble.Service
}

func newBLEDevice(dev ble.Device, srv ble.Service) CommissionableDevice {
	return &bleDevice{
		baseDevice: &baseDevice{},
		Device:     dev,
		Service:    srv,
	}
}

// Source returns the discovery source.
func (dev *bleDevice) Source() DiscoverySource {
	return types.DiscoverySourceBLE
}

// Address returns the device address.
func (dev *bleDevice) Address() string {
	return dev.Device.Address().String()
}

// Commission commissions the node with the given commissioning options.
func (dev *bleDevice) Commission(ctx context.Context, payload OnboardingPayload) error {
	if err := dev.Connect(ctx); err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer func() {
		if err := dev.Disconnect(); err != nil {
			log.Errorf("Failed to disconnect: %v", err)
		}
	}()

	log.Infof("Connected to device: %s", dev.String())

	log.Infof("Device service: %s", dev.Service.String())

	transport, err := dev.Service.Open()
	if err != nil {
		return fmt.Errorf("failed to open device transport: %s: %w", dev.String(), err)
	}
	defer transport.Close()

	res, err := transport.Handshake(ctx)
	if err != nil {
		return fmt.Errorf("failed to perform handshake: %s: %w", dev.String(), err)
	}

	log.Infof("Handshake response: %s", res.String())

	return nil
}

// String returns the string representation of the BLE device.
func (dev *bleDevice) String() string {
	return dev.baseDevice.String(dev)
}

// MarshalObject returns an object suitable for marshaling to JSON.
func (dev *bleDevice) MarshalObject() any {
	return dev.baseDevice.MarshalObject(dev)
}
