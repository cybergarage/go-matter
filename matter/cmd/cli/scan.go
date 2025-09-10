// Copyright (C) 2022 The PuzzleDB Authors.
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
	"os"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/cybergarage/go-matter/matter/ble"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	rootCmd.AddCommand(scanCmd)
}

var scanCmd = &cobra.Command{ // nolint:exhaustruct
	Use:   "scan",
	Short: "Scan for Matter devices.",
	Long:  "Scan for Matter devices.",
	RunE: func(cmd *cobra.Command, args []string) error {
		format, err := NewFormatFromString(viper.GetString(FormatParamStr))
		if err != nil {
			return err
		}
		scanner := SharedCommissioner()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err = scanner.Scan(ctx)
		if err != nil {
			return err
		}
		columns := []string{"Name", "Addr", "VendorID", "ProductID", "Discriminator"}
		printDevicesTable := func(devs []ble.Device) error {
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
			printRow := func(cols ...string) {
				for i, col := range cols {
					if i == len(cols)-1 {
						_, _ = w.Write([]byte(col + "\n"))
					} else {
						_, _ = w.Write([]byte(col + "\t"))
					}
				}
			}
			printRow(columns...)
			for _, dev := range devs {
				service := dev.Service()
				if service == nil {
					continue
				}
				printRow(
					dev.LocalName(),
					dev.Address().String(),
					strconv.Itoa(int(service.VendorID())),
					strconv.Itoa(int(service.ProductID())),
					strconv.Itoa(int(service.Discriminator())),
				)
			}
			w.Flush()
			return nil
		}
		printDevicesJSON := func(devs []ble.Device) error {
			return nil
		}
		printDevicesCSV := func(devs []ble.Device) error {
			return nil
		}
		devs := scanner.ScannedDevices()
		switch format {
		case FormatTable:
			return printDevicesTable(devs)
		case FormatJSON:
			return printDevicesJSON(devs)
		case FormatCSV:
			return printDevicesCSV(devs)
		}
		return nil
	},
}
