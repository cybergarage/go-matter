// Copyright (C) 2025 The PuzzleDB Authors.
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

package cli

import (
	"context"
	"errors"
	"time"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter/ble"
	"github.com/cybergarage/go-matter/matter/encoding"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	rootCmd.AddCommand(pairingCmd)
}

var pairingCmd = &cobra.Command{ // nolint:exhaustruct
	Use:   "pairing <node ID> <pairing code> <WIFI SSID> <WIFI password>",
	Short: "Pairing Matter devices.",
	Long:  "Pairing Matter devices.",
	Args:  cobra.ExactArgs(4),
	RunE: func(cmd *cobra.Command, args []string) error {
		verbose := viper.GetBool(VerboseParamStr)
		if verbose {
			enableStdoutVerbose(true)
		}

		nodeID := args[0]
		passcode := args[1]
		wifiSSID := args[2]
		wifiPasswd := args[3]

		log.Infof("Pairing nodeID=%s, passcode=%s, ssid=%s, passwd=%s", nodeID, passcode, wifiSSID, wifiPasswd)

		paringCode, err := encoding.NewPairingCodeFromString(passcode)
		if err != nil {
			return err
		}

		scanner := SharedCommissioner()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err = scanner.Scan(ctx)
		if err != nil {
			return err
		}

		log.Infof("Discovered matter devices:")
		for n, dev := range scanner.DiscoveredDevices() {
			log.Infof("[%d] %s", n, dev.String())
		}

		log.Infof("Pairing code: %s (%d/%d)", paringCode.String(), paringCode.Discriminator(), paringCode.Passcode())

		dev, err := scanner.LookupDeviceByDiscriminator(paringCode.Discriminator())
		if err != nil {
			if errors.Is(err, ble.ErrNotFound) {
				log.Errorf("Device not found: %s (%d)", passcode, uint16(paringCode.Discriminator()))
			} else {
				log.Errorf("Failed to lookup device: %s (%d): %v", passcode, uint16(paringCode.Discriminator()), err)
			}
		}

		log.Infof("Found device: %s", dev.String())

		if !dev.IsCommissionable() {
			log.Errorf("Device is not commissionable: %s", dev.String())
			return nil
		}

		if err := dev.Connect(context.Background()); err != nil {
			log.Errorf("Failed to connect: %v", err)
			return nil
		}
		defer func() {
			if err := dev.Disconnect(); err != nil {
				log.Errorf("Failed to disconnect: %v", err)
			}
		}()

		log.Infof("Connected to device: %s", dev.String())

		service, err := dev.Service()
		if err != nil {
			log.Errorf("Failed to get device service: %s: %v", dev.String(), err)
			return nil
		}

		log.Infof("Device service: %s", service.String())

		transport, err := service.Open()
		if err != nil {
			log.Errorf("Failed to open device transport: %s: %v", dev.String(), err)
			return nil
		}
		defer transport.Close()

		res, err := transport.Handshake()
		if err != nil {
			log.Errorf("Failed to perform handshake: %s: %v", dev.String(), err)
			return nil
		}

		log.Infof("Handshake response: %s", res.String())

		return nil
	}}
