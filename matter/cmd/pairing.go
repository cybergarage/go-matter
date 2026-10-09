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

package cmd

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter"
	"github.com/cybergarage/go-matter/matter/config"
	"github.com/cybergarage/go-matter/matter/encoding"
	"github.com/cybergarage/go-matter/matter/types"
	"github.com/spf13/cobra"
)

func init() {
	pairingCmd.AddCommand(pairingCodeCmd)
	pairingCmd.AddCommand(pairingCodeWifiCmd)
	rootCmd.AddCommand(pairingCmd)
}

var pairingCmd = &cobra.Command{ // nolint:exhaustruct
	Use:   "pairing",
	Short: "Pairing Matter devices.",
	Long:  "Pairing Matter devices by specifying node ID and pairing code.",
}

var pairingCodeCmd = &cobra.Command{ // nolint:exhaustruct
	Use:   "code <node ID|auto> <pairing code>",
	Short: "Pair using node ID and pairing code.",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		nodeID, err := parsePairingNodeID(args[0])
		if err != nil {
			return err
		}
		passcode := args[1]

		log.Info("Pairing requested (onboarding data omitted)")

		pairingCode, err := encoding.NewPairingCodeFromString(passcode)
		if err != nil {
			return err
		}

		cmr := SharedCommissioner()
		ctx, cancel := context.WithTimeout(context.Background(), matter.DefaultCommissioningTimeout)
		defer cancel()

		cme, err := cmr.Commission(ctx, pairingCode, matter.CommissionNodeID(nodeID))
		if err != nil {
			log.Error(err)
			return err
		}

		log.Infof("Successfully commissioned device: %s", cme.String())

		return nil
	},
}

var pairingCodeWifiCmd = &cobra.Command{ // nolint:exhaustruct
	Use:   "code-wifi <node ID|auto> <pairing code> <WIFI SSID> <WIFI password>",
	Short: "Pair using node ID, pairing code, and WiFi credentials.",
	Args:  cobra.ExactArgs(4),
	RunE: func(cmd *cobra.Command, args []string) error {
		nodeID, err := parsePairingNodeID(args[0])
		if err != nil {
			return err
		}
		passcode := args[1]
		wifiSSID := args[2]
		wifiPasswd := args[3]

		log.Info("Wi-Fi pairing requested (onboarding data omitted)")

		pairingCode, err := encoding.NewPairingCodeFromString(passcode)
		if err != nil {
			return err
		}

		cmr := SharedCommissioner()
		ctx, cancel := context.WithTimeout(context.Background(), matter.DefaultCommissioningTimeout)
		defer cancel()

		wifiCfg := config.NewWiFiNetworkConfig(
			config.WithSSID([]byte(wifiSSID)),
			config.WithCredentials([]byte(wifiPasswd)),
		)
		cme, err := cmr.Commission(ctx, pairingCode, wifiCfg, matter.CommissionNodeID(nodeID))
		if err != nil {
			log.Error(err)
			return err
		}

		log.Infof("Successfully commissioned device: %s", cme.String())

		return nil
	},
}

// Numeric arguments retain decimal semantics; 0x prefixes permit explicit hexadecimal.
func parsePairingNodeID(s string) (uint64, error) {
	if s == "auto" {
		return 0, nil
	}
	base := 10
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		base = 16
		s = s[2:]
	}
	n, err := strconv.ParseUint(s, base, 64)
	if err != nil || !types.NodeID(n).IsOperational() {
		return 0, errors.New("node ID must be operational decimal/0x hexadecimal, or auto")
	}
	return n, nil
}
