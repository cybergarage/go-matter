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
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/cybergarage/go-matter/matter"
	"github.com/cybergarage/go-matter/matter/encoding"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	rootCmd.AddCommand(scanCmd)
}

var scanCmd = &cobra.Command{ // nolint:exhaustruct
	Use:   "scan [pairing code]",
	Short: "Scan for Matter devices.",
	Long:  "Scan for Matter devices. Optionally filter devices using a manual pairing code.",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		format, err := NewFormatFromString(viper.GetString(FormatParamStr))
		if err != nil {
			return err
		}

		opts := []matter.QueryOption{}
		switch {
		case len(args) == 1:
			pairingCodeStr := args[0]
			pairingCode, err := encoding.NewPairingCodeFromString(pairingCodeStr)
			if err != nil {
				return fmt.Errorf("%w: %s", err, pairingCodeStr)
			}
			opts = append(opts, matter.WithQueryOnboardingPayload(pairingCode))
		}

		cmr := SharedCommissioner()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		devs, err := cmr.Discover(ctx, matter.NewQuery(opts...))
		if err != nil {
			return err
		}
		if len(devs) == 0 {
			return nil
		}

		columns := []string{"Name", "Addr", "VendorID", "ProductID", "Discriminator"}
		deviceColumns := func(dev matter.CommissionableDevice) ([]string, error) {
			return []string{
				strconv.Itoa(int(dev.VendorID())),
				strconv.Itoa(int(dev.ProductID())),
				strconv.Itoa(int(dev.Discriminator())),
			}, nil
		}

		printDevicesTable := func(devs []matter.CommissionableDevice) error {
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
			printRow := func(cols ...string) {
				if len(cols) == 0 {
					return
				}
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
				devColumns, err := deviceColumns(dev)
				if err != nil {
					return err
				}
				printRow(devColumns...)
			}
			w.Flush()
			return nil
		}

		printDevicesCSV := func(devs []matter.CommissionableDevice) error {
			printRow := func(cols ...string) {
				if len(cols) == 0 {
					return
				}
				outputf("%s\n", strings.Join(cols, ","))
			}
			printRow(columns...)
			for _, dev := range devs {
				devColumns, err := deviceColumns(dev)
				if err != nil {
					return err
				}
				printRow(devColumns...)
			}
			return nil
		}

		printDevicesJSON := func(devs []matter.CommissionableDevice) error {
			devObjs := make([]any, 0, len(devs))
			for _, dev := range devs {
				devObjs = append(devObjs, dev.MarshalObject())
			}
			b, err := json.MarshalIndent(devObjs, "", "  ")
			if err != nil {
				return err
			}
			outputf("%s\n", string(b))
			return nil
		}

		switch format {
		case FormatJSON:
			return printDevicesJSON(devs)
		case FormatCSV:
			return printDevicesCSV(devs)
		default:
			return printDevicesTable(devs)
		}
	},
}
