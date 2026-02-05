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
	"github.com/cybergarage/go-matter/matter/pase"
	"github.com/cybergarage/go-matter/matter/types"
)

type bleDevice struct {
	*baseDevice
	ble.Device
	ble.Service
	transport ble.Transport
}

func newBLEDevice(dev ble.Device, srv ble.Service) CommissionableDevice {
	return &bleDevice{
		baseDevice: &baseDevice{},
		Device:     dev,
		Service:    srv,
		transport:  nil,
	}
}

// Type returns the device type.
func (dev *bleDevice) Type() DeviceType {
	return types.BLEDevice
}

// Address returns the device address.
func (dev *bleDevice) Address() string {
	return dev.Device.Address().String()
}

// Transmit writes data to the transport.
func (dev *bleDevice) Transmit(ctx context.Context, b []byte) error {
	if dev.transport == nil {
		return fmt.Errorf("transport is not opened")
	}
	_, err := dev.transport.Write(ctx, b)
	return err
}

// Receive reads data from the transport.
func (dev *bleDevice) Receive(ctx context.Context) ([]byte, error) {
	if dev.transport == nil {
		return nil, fmt.Errorf("transport is not opened")
	}
	return dev.transport.Read(ctx)
}

// Commission commissions the node with the given commissioning options.
func (dev *bleDevice) Commission(ctx context.Context, payload OnboardingPayload) error {
	log.Infof("Connected to device: %s", dev.String())
	if err := dev.Connect(ctx); err != nil {
		log.Errorf("Failed to connect to device (%s): %v", dev.String(), err)
		return err
	}
	defer func() {
		if err := dev.Disconnect(); err != nil {
			log.Errorf("Failed to disconnect: %v", err)
		}
	}()

	log.Infof("Device service: %s", dev.Service.String())

	var err error
	dev.transport, err = dev.Service.Open()
	if err != nil {
		log.Errorf("Failed to open device transport (%s): %v", dev.String(), err)
		return err
	}
	defer func() {
		if err := dev.transport.Close(); err != nil {
			log.Error(err)
		}
		dev.transport = nil
	}()

	res, err := dev.transport.Handshake(ctx)
	if err != nil {
		log.Errorf("Failed to perform handshake with device (%s): %v", dev.String(), err)
		return err
	}

	log.Infof("Handshake response: %s", res.String())

	paseClient := pase.NewClient(dev, payload.Passcode())
	_, err = paseClient.EstablishSession(ctx)
	if err != nil {
		log.Errorf("Failed to establish PASE session with device (%s): %v", dev.String(), err)
		return err
	}

	return nil
}

// MatchesOnboardingPayload checks whether the device matches the given onboarding payload.
func (dev *bleDevice) MatchesOnboardingPayload(payload OnboardingPayload) bool {
	return dev.matchesOnboardingPayload(dev, payload)
}

// String returns the string representation of the BLE device.
func (dev *bleDevice) String() string {
	return dev.baseDevice.string(dev)
}

// MarshalObject returns an object suitable for marshaling to JSON.
func (dev *bleDevice) MarshalObject() any {
	return dev.baseDevice.marshalObject(dev)
}
