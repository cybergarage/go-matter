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
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/cybergarage/go-ble/ble"
)

const (
	// MatterServiceID is the Bluetooth service ID for Matter.
	MatterServiceID = uint16(0xFFF6)
	// OpCodeCommissionable is the operation code for commissionable devices.
	OpCodeCommissionable = uint8(0x00)
)

// MatterServiceUUID is the Bluetooth service UUID for Matter.
var MatterServiceUUID = ble.NewUUIDFromUUID16(MatterServiceID)

// Service represents a Matter BLE service.
type Service interface {
	// ServiceDescriptor represents a Matter BLE service descriptor.
	ServiceDescriptor
	// ServiceDescriptorHelper provides helper methods for a Matter BLE service.
	ServiceDescriptorHelper
	// ServiceOperator represents a Matter BLE service operator.
	ServiceOperator
	// MarshalObject returns an object suitable for marshaling to JSON.
	MarshalObject() any
	// String returns a string representation of the service.
	String() string
}

// ServiceDescriptor represents a Matter BLE service descriptor.
type ServiceDescriptor interface {
	ble.ServiceDescriptor
	// AdvertisementVersion returns the advertisement version.
	AdvertisementVersion() uint8
	// Discriminator returns the discriminator.
	Discriminator() Discriminator
	// VendorID returns the vendor ID.
	VendorID() uint16
	// ProductID returns the product ID.
	ProductID() uint16
	// AdditionalDataFlag returns the additional data flag.
	AdditionalDataFlag() bool
	// ExtendedAnnouncement returns the extended announcement flag.
	ExtendedAnnouncement() bool
}

// ServiceDescriptorHelper provides helper methods for a Matter BLE service.
type ServiceDescriptorHelper interface {
	// IsCommissionable returns whether the service is commissionable.
	IsCommissionable() bool
}

// ServiceOperator represents a Matter BLE service operator.
type ServiceOperator interface {
	// Open opens the service and returns a transport of Matter BLE service.
	Open() (Transport, error)
}

type service struct {
	ble.Service
	*advertisingData
}

// NewService returns a new BLE service.
func NewServiceWith(bleService ble.Service) (Service, error) {
	adData, err := newAdvertisingDataFromBytes(bleService.Data())
	if err != nil {
		return nil, err
	}
	return &service{
		Service:         bleService,
		advertisingData: adData,
	}, nil
}

// Open opens the service and returns a transport of Matter BLE service.
func (s *service) Open() (Transport, error) {
	transport, err := s.Service.Open(
		ble.WithTransportWriteUUID(C1UUID),
		ble.WithTransportNotifyUUID(C2UUID),
	)
	return newTransport(transport), err
}

// MarshalObject returns an object suitable for marshaling to JSON.
func (s *service) MarshalObject() any {
	charObjs := make([]any, 0)
	for _, char := range s.Characteristics() {
		charObjs = append(charObjs, char.MarshalObject())
	}
	return struct {
		UUID                 string `json:"uuid"`
		Name                 string `json:"name"`
		OpCode               uint8  `json:"opCode"`
		AdvertisementVersion uint8  `json:"advertisementVersion"`
		Discriminator        uint16 `json:"discriminator"`
		VendorID             uint16 `json:"vendorId"`
		ProductID            uint16 `json:"productId"`
		AdditionalDataFlag   bool   `json:"additionalDataFlag"`
		ExtendedAnnouncement bool   `json:"extendedAnnouncement"`
		Characteristic       any    `json:"characteristic"`
	}{
		UUID:                 s.UUID().String(),
		Name:                 s.Name(),
		OpCode:               s.OpCode(),
		AdvertisementVersion: s.AdvertisementVersion(),
		Discriminator:        uint16(s.Discriminator()),
		VendorID:             s.VendorID(),
		ProductID:            s.ProductID(),
		AdditionalDataFlag:   s.AdditionalDataFlag(),
		ExtendedAnnouncement: s.ExtendedAnnouncement(),
		Characteristic:       charObjs,
	}
}

// String returns a string representation of the service.
func (s *service) String() string {
	b, err := json.Marshal(s.MarshalObject())
	if err != nil {
		return "{}"
	}
	return string(b)
}

type advertisingData struct {
	opCode               uint8
	advertisementVersion uint8  // Bits[15:12]
	discriminator        uint16 // Bits[11:0]
	vendorID             uint16
	productID            uint16
	additionalDataFlag   bool
	extendedAnnouncement bool
}

// newAdvertisingDataFromBytes parses a byte slice according to the Matter BLE data specification.
func newAdvertisingDataFromBytes(data []byte) (*advertisingData, error) {
	// 5.4.2.5.6. Advertising Data
	// All multi-byte values are encoded in little-endian byte order within the service data payload.

	if len(data) < 8 {
		return nil, fmt.Errorf("%w: %s", ErrInvalid, "advertising data too short")
	}
	opCode := data[0]

	advAndDisc := binary.LittleEndian.Uint16(data[1:3])
	advVersion := uint8((advAndDisc & 0xF000) >> 12)
	discriminator := advAndDisc & 0x0FFF

	vendorID := binary.LittleEndian.Uint16(data[3:5])
	productID := binary.LittleEndian.Uint16(data[5:7])

	flags := data[7]
	additionalDataFlag := (flags & 0x01) != 0
	extendedAnnouncement := (flags & 0x02) != 0

	return &advertisingData{
		opCode:               opCode,
		advertisementVersion: advVersion,
		discriminator:        discriminator,
		vendorID:             vendorID,
		productID:            productID,
		additionalDataFlag:   additionalDataFlag,
		extendedAnnouncement: extendedAnnouncement,
	}, nil
}

// OpCode returns the operation code.
func (ad *advertisingData) OpCode() uint8 {
	return ad.opCode
}

// AdvertisementVersion returns the advertisement version.
func (ad *advertisingData) AdvertisementVersion() uint8 {
	return ad.advertisementVersion
}

// Discriminator returns the discriminator.
func (ad *advertisingData) Discriminator() Discriminator {
	return Discriminator(ad.discriminator)
}

// VendorID returns the vendor ID.
func (ad *advertisingData) VendorID() uint16 {
	return ad.vendorID
}

// ProductID returns the product ID.
func (ad *advertisingData) ProductID() uint16 {
	return ad.productID
}

// AdditionalDataFlag returns the additional data flag.
func (ad *advertisingData) AdditionalDataFlag() bool {
	return ad.additionalDataFlag
}

// ExtendedAnnouncement returns the extended announcement flag.
func (ad *advertisingData) ExtendedAnnouncement() bool {
	return ad.extendedAnnouncement
}

// IsCommissionable returns true if the device is commissionable.
func (ad *advertisingData) IsCommissionable() bool {
	return ad.opCode == OpCodeCommissionable
}
