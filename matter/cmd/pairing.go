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
	"github.com/cybergarage/go-matter/matter/credentials"
	"github.com/cybergarage/go-matter/matter/encoding"
	"github.com/cybergarage/go-matter/matter/types"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	// AttestationParamStr selects how device attestation is verified.
	AttestationParamStr = "attestation"
	// PAATrustStoreParamStr names a directory of PAA certificates to trust
	// besides the bundled ones.
	PAATrustStoreParamStr = "paa-trust-store"
	// CDTrustStoreParamStr names a directory of Certification Declaration
	// signing certificates to trust besides the bundled ones.
	CDTrustStoreParamStr = "cd-trust-store"
)

func init() {
	viper.SetDefault(AttestationParamStr, matter.AttestationDevelopment.String())
	pairingCmd.PersistentFlags().String(AttestationParamStr, matter.AttestationDevelopment.String(),
		"device attestation verification: development|production|none")
	viper.BindPFlag(AttestationParamStr, pairingCmd.PersistentFlags().Lookup(AttestationParamStr))
	viper.BindEnv(AttestationParamStr) // MATTER_CTL_ATTESTATION

	viper.SetDefault(PAATrustStoreParamStr, "")
	pairingCmd.PersistentFlags().String(PAATrustStoreParamStr, "",
		"directory of PAA certificates (.der/.pem) to trust besides the bundled ones")
	viper.BindPFlag(PAATrustStoreParamStr, pairingCmd.PersistentFlags().Lookup(PAATrustStoreParamStr))
	viper.BindEnv(PAATrustStoreParamStr, "MATTER_CTL_PAA_TRUST_STORE")

	viper.SetDefault(CDTrustStoreParamStr, "")
	pairingCmd.PersistentFlags().String(CDTrustStoreParamStr, "",
		"directory of Certification Declaration signing certificates (.der/.pem) to trust besides the bundled ones")
	viper.BindPFlag(CDTrustStoreParamStr, pairingCmd.PersistentFlags().Lookup(CDTrustStoreParamStr))
	viper.BindEnv(CDTrustStoreParamStr, "MATTER_CTL_CD_TRUST_STORE")

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

		verifier, err := pairingAttestationVerifier()
		if err != nil {
			return err
		}

		cmr := SharedCommissioner()
		ctx, cancel := context.WithTimeout(context.Background(), matter.DefaultCommissioningTimeout)
		defer cancel()

		cme, err := cmr.Commission(ctx, pairingCode, verifier, matter.CommissionNodeID(nodeID))
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

		verifier, err := pairingAttestationVerifier()
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
		cme, err := cmr.Commission(ctx, pairingCode, wifiCfg, verifier, matter.CommissionNodeID(nodeID))
		if err != nil {
			log.Error(err)
			return err
		}

		log.Infof("Successfully commissioned device: %s", cme.String())

		return nil
	},
}

// pairingAttestationVerifier returns the device attestation verification
// the --attestation, --paa-trust-store and --cd-trust-store flags select.
func pairingAttestationVerifier() (matter.AttestationVerifier, error) {
	mode, err := credentials.ParseAttestationMode(viper.GetString(AttestationParamStr))
	if err != nil {
		return nil, err
	}
	var extra []matter.AttestationTrustStore
	paaDir, cdDir := viper.GetString(PAATrustStoreParamStr), viper.GetString(CDTrustStoreParamStr)
	if paaDir != "" || cdDir != "" {
		store, err := credentials.LoadAttestationTrustStore(paaDir, cdDir)
		if err != nil {
			return nil, err
		}
		extra = append(extra, store)
	}
	return matter.NewAttestationVerifier(mode, extra...), nil
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
