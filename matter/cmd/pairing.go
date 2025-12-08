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
	"time"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter/encoding"
	"github.com/spf13/cobra"
)

func init() {
	pairingCmd.AddCommand(pairingCodeCmd)
	pairingCmd.AddCommand(pairingCodeWifiCmd)
	rootCmd.AddCommand(pairingCmd)
}

var pairingCmd = &cobra.Command{
	Use:   "pairing",
	Short: "Pairing Matter devices.",
	Long:  "Pairing Matter devices.",
}

var pairingCodeCmd = &cobra.Command{
	Use:   "code <node ID> <pairing code>",
	Short: "Pair using node ID and pairing code.",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		nodeID := args[0]
		passcode := args[1]

		log.Infof("Pairing nodeID=%s, passcode=%s", nodeID, passcode)

		pairingCode, err := encoding.NewPairingCodeFromString(passcode)
		if err != nil {
			return err
		}

		comm := SharedCommissioner()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		err = comm.Commission(ctx, pairingCode)
		if err != nil {
			return err
		}

		return nil
	},
}

var pairingCodeWifiCmd = &cobra.Command{
	Use:   "code-wifi <node ID> <pairing code> <WIFI SSID> <WIFI password>",
	Short: "Pair using node ID, pairing code, and WiFi credentials.",
	Args:  cobra.ExactArgs(4),
	RunE: func(cmd *cobra.Command, args []string) error {
		nodeID := args[0]
		passcode := args[1]
		wifiSSID := args[2]
		wifiPasswd := args[3]

		log.Infof("Pairing nodeID=%s, passcode=%s, ssid=%s, passwd=%s", nodeID, passcode, wifiSSID, wifiPasswd)

		pairingCode, err := encoding.NewPairingCodeFromString(passcode)
		if err != nil {
			return err
		}

		comm := SharedCommissioner()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// WiFi情報をCommissionerに渡す処理が必要な場合はここに追加
		err = comm.Commission(ctx, pairingCode)
		if err != nil {
			return err
		}

		return nil
	},
}
