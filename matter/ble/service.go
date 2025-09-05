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
	"errors"

	"github.com/cybergarage/go-ble/ble"
)

// Service represents a BLE service.
type Service interface {
	ble.Service
	// AdvertisementVersion returns the advertisement version.
	AdvertisementVersion() uint8
	// Discriminator returns the discriminator.
	Discriminator() uint16
	// VendorID returns the vendor ID.
	VendorID() uint16
	// ProductID returns the product ID.
	ProductID() uint16
	// AdditionalDataFlag returns the additional data flag.
	AdditionalDataFlag() bool
	// ExtendedAnnouncement returns the extended announcement flag.
	ExtendedAnnouncement() bool
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
	if len(data) < 8 {
		return nil, errors.New("invalid data length")
	}
	opCode := data[0]

	advAndDisc := binary.BigEndian.Uint16(data[1:3])
	advVersion := uint8((advAndDisc & 0xF000) >> 12)
	discriminator := advAndDisc & 0x0FFF

	vendorID := binary.BigEndian.Uint16(data[3:5])
	productID := binary.BigEndian.Uint16(data[5:7])

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
func (ad *advertisingData) Discriminator() uint16 {
	return ad.discriminator
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
