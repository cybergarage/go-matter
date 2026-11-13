// Copyright (C) 2026 The go-matter Authors. All rights reserved.
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
	"encoding/binary"
	"sort"
	"testing"

	"github.com/cybergarage/go-ble/ble"
)

// fakeScanner is a ble.Scanner whose scans report the devices given to it.
type fakeScanner struct {
	ble.Scanner
	scans [][]ble.Device
}

func (s *fakeScanner) Scan(_ context.Context, opts ...ble.ScannerOption) error {
	devs := s.scans[0]
	s.scans = s.scans[1:]
	for _, dev := range devs {
		for _, opt := range opts {
			if handler, ok := opt.(ble.ScanHandler); ok {
				handler(dev)
			}
		}
	}
	return nil
}

// fakeService is the Matter service of an advertisement.
type fakeService struct {
	ble.Service
	data []byte
}

func (s *fakeService) UUID() ble.UUID { return MatterServiceUUID }
func (s *fakeService) Data() []byte   { return s.data }

// fakeDevice is a device advertising the Matter service.
type fakeDevice struct {
	ble.Device
	addr    ble.Address
	service *fakeService
}

func (d *fakeDevice) Address() ble.Address { return d.addr }
func (d *fakeDevice) String() string       { return d.addr.String() }

func (d *fakeDevice) LookupService(uuid any) (ble.Service, bool) {
	lookup, err := ble.NewUUIDFrom(uuid)
	if err != nil || !lookup.Equal(MatterServiceUUID) {
		return nil, false
	}
	return d.service, true
}

// advertising returns a device advertising a commissionable Matter node.
// 5.4.2.5.6. Advertising Data.
func advertising(t *testing.T, addr string, discriminator uint16) ble.Device {
	t.Helper()
	a, err := ble.NewAddressFromString(addr)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 8)
	binary.LittleEndian.PutUint16(data[1:3], discriminator&0x0FFF)
	binary.LittleEndian.PutUint16(data[3:5], 0x1392)
	binary.LittleEndian.PutUint16(data[5:7], 0x0301)
	return &fakeDevice{addr: a, service: &fakeService{data: data}}
}

func addresses(devs []Device) []string {
	out := make([]string, 0, len(devs))
	for _, d := range devs {
		out = append(out, d.Address().String())
	}
	sort.Strings(out)
	return out
}

func TestScanForgetsTheDevicesOfEarlierScans(t *testing.T) {
	const discriminator = 3020
	scn := &scanner{Scanner: &fakeScanner{scans: [][]ble.Device{
		// The first scan finds the bulb and another device.
		{advertising(t, "11:22:33:44:55:66", discriminator), advertising(t, "AA:BB:CC:DD:EE:FF", 1234)},
		// By the next scan the bulb advertises from another random
		// address, and the other device has closed its window.
		{advertising(t, "11:22:33:44:55:77", discriminator)},
		// Then nothing advertises.
		{},
	}}}
	ctx := context.Background()

	if err := scn.Scan(ctx); err != nil {
		t.Fatal(err)
	}
	if got := addresses(scn.DiscoveredDevices()); len(got) != 2 {
		t.Fatalf("first scan: %v", got)
	}

	if err := scn.Scan(ctx); err != nil {
		t.Fatal(err)
	}
	got := addresses(scn.DiscoveredDevices())
	if len(got) != 1 || got[0] != "11:22:33:44:55:77" {
		t.Fatalf("second scan: %v", got)
	}
	dev, err := scn.LookupDeviceByDiscriminator(discriminator)
	if err != nil || dev.Address().String() != "11:22:33:44:55:77" {
		t.Fatalf("lookup after the second scan: %v, %v", dev, err)
	}
	if _, err := scn.LookupDeviceByDiscriminator(1234); err == nil {
		t.Fatal("a device of an earlier scan is still found")
	}

	if err := scn.Scan(ctx); err != nil {
		t.Fatal(err)
	}
	if got := scn.DiscoveredDevices(); len(got) != 0 {
		t.Fatalf("empty scan: %v", addresses(got))
	}
}
