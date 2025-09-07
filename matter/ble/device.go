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
	"encoding/json"
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
	// DeviceDescriptor returns the read-only device descriptor.
	DeviceDescriptor
	// DeviceOperator returns the device operator.
	DeviceOperator
	// String returns the string representation of the device.
	String() string
}

// DeviceDescriptor represents a read-only Bluetooth device descriptor.
type DeviceDescriptor interface {
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
}

// DeviceOperator represents a Bluetooth device operator.
type DeviceOperator interface {
	// IsCommissionable returns whether the service is commissionable.
	IsCommissionable() bool
	// Connect connects to the device.
	Connect(ctx context.Context) error
	// Disconnect disconnects from the device.
	Disconnect() error
	// IsConnected returns whether the device is connected.
	IsConnected() bool
	// LookupService looks up a Bluetooth service by its UUID.
	LookupService(uuid UUID) (Service, bool)
}

type device struct {
	ble.Device
	service Service
}

func newDeviceWith(bleDev ble.Device, bleSrv ble.Service) (Device, error) {
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

// IsCommissionable returns whether the service is commissionable.
func (dev *device) IsCommissionable() bool {
	if dev.service == nil {
		return false
	}
	return dev.service.IsCommissionable()
}

// LookupService looks up a Bluetooth service by its UUID.
func (dev *device) LookupService(uuid UUID) (Service, bool) {
	bleSrv, ok := dev.Device.LookupService(uuid)
	if !ok {
		return nil, false
	}
	matterSrv, err := NewServiceWith(bleSrv)
	if err != nil {
		return nil, false
	}
	return matterSrv, true
}

// MarshalObject returns an object suitable for marshaling to JSON.
func (dev *device) MarshalObject() any {
	return struct {
		Address      string `json:"address"`
		LocalName    string `json:"localName"`
		Manufacturer any    `json:"manufacturer"`
		RSSI         int    `json:"rssi"`
		Services     []any  `json:"services"`
		DiscoveredAt string `json:"discoveredAt"`
		ModifiedAt   string `json:"modifiedAt"`
		LastSeenAt   string `json:"lastSeenAt"`
	}{
		Address:      dev.Address().String(),
		LocalName:    dev.LocalName(),
		Manufacturer: dev.Manufacturer().MarshalObject(),
		RSSI:         dev.RSSI(),
		Services:     []any{dev.service.MarshalObject()},
		DiscoveredAt: dev.DiscoveredAt().Format(time.RFC3339),
		ModifiedAt:   dev.ModifiedAt().Format(time.RFC3339),
		LastSeenAt:   dev.LastSeenAt().Format(time.RFC3339),
	}
}

// String returns a string representation of the service.
func (dev *device) String() string {
	b, err := json.Marshal(dev.MarshalObject())
	if err != nil {
		return "{}"
	}
	return string(b)
}
