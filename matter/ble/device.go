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
	"errors"
	"time"

	"github.com/cybergarage/go-ble/ble"
)

// Manufacturer represents a Bluetooth manufacturer.
type Manufacturer = ble.Manufacturer

// Address represents a Bluetooth address.
type Address = ble.Address

// UUID represents a Bluetooth UUID.
type UUID = ble.UUID

// Device represents a matter BLE device.
type Device interface {
	// Manufacturer returns the Bluetooth manufacturer of the device.
	Manufacturer() Manufacturer
	// LocalName returns the local name of the device.
	LocalName() string
	// Address returns the Bluetooth address of the device.
	Address() Address
	// RSSI returns the received signal strength indicator of the device.
	RSSI() int
	// DiscoveredAt returns the time when the device was first discovered.
	DiscoveredAt() time.Time
	// ModifiedAt returns the time when the device was last modified.
	ModifiedAt() time.Time
	// LastSeenAt returns the time when the device was last seen.
	LastSeenAt() time.Time
	// Service returns the primary service of the device.
	Service() Service
	// String returns the string representation of the device.
	String() string
}

type device struct {
	ble.Device
	service Service
}

// NewDeviceWith returns a new matter BLE device.
func NewDeviceWith(bleDev ble.Device) (Device, error) {
	bleSrv, ok := bleDev.LookupService(MatterServiceUUID)
	if !ok {
		return nil, errors.New("no matter service")
	}
	matterSrv, err := NewServiceWith(bleSrv)
	if err != nil {
		return nil, err
	}
	return &device{
		Device:  bleDev,
		service: matterSrv,
	}, nil
}

// Service returns the primary service of the device.
func (dev *device) Service() Service {
	return dev.service
}

// String returns the string representation of the device.
func (dev *device) String() string {
	return dev.Device.String() + ", " + dev.service.String()
}
