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

package cmd

import (
	"context"
	"time"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter/encoding"
	"github.com/spf13/cobra"
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
		nodeID := args[0]
		passcode := args[1]
		wifiSSID := args[2]
		wifiPasswd := args[3]

		log.Infof("Pairing nodeID=%s, passcode=%s, ssid=%s, passwd=%s", nodeID, passcode, wifiSSID, wifiPasswd)

		paringCode, err := encoding.NewPairingCodeFromString(passcode)
		if err != nil {
			return err
		}

		comm := SharedCommissioner()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		err = comm.Commission(ctx, paringCode)
		if err != nil {
			return err
		}

		return nil
	}}
