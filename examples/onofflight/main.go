// Copyright (C) 2026 The go-matter Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// onofflight is a Matter On/Off Light (device type 0x0100) built with
// go-matter: a node with the light on endpoint 1, which a commissioner
// such as chip-tool commissions over IP and switches on and off.
//
// It attests with the public test credentials of the Matter SDK, so a
// commissioner accepts it only in development mode:
//
//	onofflight -passcode 20202021 -discriminator 3840
//	chip-tool pairing onnetwork-long 1 20202021 3840
//	chip-tool onoff toggle 1 1
//	chip-tool onoff subscribe on-off 1 10 1 1
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter/credentials/testcreds"
	"github.com/cybergarage/go-matter/matter/device"
	"github.com/cybergarage/go-matter/matter/device/cluster"
	"github.com/cybergarage/go-matter/matter/store"
	"github.com/cybergarage/go-matter/matter/types"
)

// lightEndpoint is the endpoint of the light.
const lightEndpoint = 1

func main() {
	passcode := flag.Uint("passcode", 20202021, "setup passcode")
	discriminator := flag.Uint("discriminator", 3840, "12-bit discriminator")
	address := flag.String("address", device.DefaultAddress, "UDP address to listen on")
	storeDir := flag.String("store", "", "directory keeping the fabrics across restarts (in memory if empty)")
	name := flag.String("name", "go-matter On/Off Light", "product name")
	debug := flag.Bool("debug", false, "log debug messages")
	flag.Parse()

	if *debug {
		log.EnableStdoutDebug(true)
	}
	if err := run(*passcode, *discriminator, *address, *storeDir, *name); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(passcode, discriminator uint, address, storeDir, name string) error {
	if device.MaxDiscriminator < discriminator {
		return fmt.Errorf("discriminator %d exceeds 12 bits", discriminator)
	}
	attestation, err := testcreds.AttestationProvider()
	if err != nil {
		return err
	}
	deviceStore := store.NewMemDeviceStore()
	if storeDir != "" {
		kv, err := store.NewFileKVStore(storeDir)
		if err != nil {
			return err
		}
		deviceStore = store.NewDeviceStore(kv)
	}

	dev, err := device.New(
		device.WithPasscode(types.Passcode(passcode)),
		device.WithDiscriminator(uint16(discriminator)),
		device.WithAddress(address),
		device.WithVendorID(testcreds.VendorID),
		device.WithProductID(testcreds.ProductID),
		device.WithDeviceType(device.OnOffLightDeviceType.ID),
		device.WithDeviceName(name),
		device.WithDeviceStore(deviceStore),
		device.WithAttestationProvider(attestation),
	)
	if err != nil {
		return err
	}

	// The On/Off Light: Identify, Groups and On/Off on endpoint 1
	// (Matter Device Library 4.1).
	ep, err := dev.AddEndpoint(lightEndpoint, device.OnOffLightDeviceType)
	if err != nil {
		return err
	}
	cluster.NewIdentify(cluster.IdentifyTypeLightOutput, cluster.WithIdentifyHandler(func(identifying bool) {
		fmt.Printf("identify: %v\n", identifying)
	})).Register(ep)
	cluster.NewGroups().Register(ep)
	cluster.NewOnOff(cluster.WithOnOffHandler(func(on bool) {
		if on {
			fmt.Println("light: ON")
		} else {
			fmt.Println("light: OFF")
		}
	})).Register(ep)

	if err := dev.Start(); err != nil {
		return err
	}
	svc := dev.CommissionableService()
	fmt.Printf("On/Off Light listening on port %d, discriminator %d, passcode %d\n", svc.Port, discriminator, passcode)
	if dev.IsCommissioningWindowOpen() {
		fmt.Printf("commission it with: chip-tool pairing onnetwork-long <node-id> %d %d\n", passcode, discriminator)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	return dev.Stop()
}
