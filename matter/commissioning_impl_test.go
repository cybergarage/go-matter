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

package matter

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/cybergarage/go-matter/matter/config"
	mdnspkg "github.com/cybergarage/go-matter/matter/mdns"
	"github.com/cybergarage/go-matter/matter/protocol/im"
	"github.com/cybergarage/go-matter/matter/protocol/session"
)

func TestCommissionOperationalCredentialsNilConfig(t *testing.T) {
	err := commissionOperationalCredentials(nil, nil)
	if err == nil {
		t.Fatal("commissionOperationalCredentials(nil, nil) error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "operational credentials config is required") {
		t.Fatalf("commissionOperationalCredentials(nil, nil) error = %q, want missing config error", err)
	}
}

func TestCommissionOperationalCredentialsMissingRequiredInputs(t *testing.T) {
	tests := []struct {
		name    string
		cfg     config.OperationalCredentialsConfig
		wantErr string
	}{
		{
			name: "missing root certificate",
			cfg: config.NewOperationalCredentialConfig(
				config.WithNOC([]byte{0x01}),
				config.WithIPK([]byte{0x02}),
				config.WithCASEAdminNodeID(1),
				config.WithAdminVendorID(1),
			),
			wantErr: "missing root certificate",
		},
		{
			name: "missing noc",
			cfg: config.NewOperationalCredentialConfig(
				config.WithRootCertificate([]byte{0x01}),
				config.WithIPK([]byte{0x02}),
				config.WithCASEAdminNodeID(1),
				config.WithAdminVendorID(1),
			),
			wantErr: "missing NOC",
		},
		{
			name: "missing ipk",
			cfg: config.NewOperationalCredentialConfig(
				config.WithRootCertificate([]byte{0x01}),
				config.WithNOC([]byte{0x02}),
				config.WithCASEAdminNodeID(1),
				config.WithAdminVendorID(1),
			),
			wantErr: "missing IPK",
		},
		{
			name: "missing case admin node id",
			cfg: config.NewOperationalCredentialConfig(
				config.WithRootCertificate([]byte{0x01}),
				config.WithNOC([]byte{0x02}),
				config.WithIPK([]byte{0x03}),
				config.WithAdminVendorID(1),
			),
			wantErr: "missing CASE admin node ID",
		},
		{
			name: "missing admin vendor id",
			cfg: config.NewOperationalCredentialConfig(
				config.WithRootCertificate([]byte{0x01}),
				config.WithNOC([]byte{0x02}),
				config.WithIPK([]byte{0x03}),
				config.WithCASEAdminNodeID(1),
			),
			wantErr: "missing admin vendor ID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := commissionOperationalCredentials(nil, tt.cfg)
			if err == nil {
				t.Fatalf("commissionOperationalCredentials(nil, cfg) error = nil, want %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("commissionOperationalCredentials(nil, cfg) error = %q, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestCommissionNetworkNilConfig(t *testing.T) {
	if err := commissionNetwork(nil, nil, false); err != nil {
		t.Fatalf("commissionNetwork(nil, nil, false) error = %v, want nil", err)
	}

	err := commissionNetwork(nil, nil, true)
	if err == nil {
		t.Fatal("commissionNetwork(nil, nil, true) error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "Wi-Fi network config is required") {
		t.Fatalf("commissionNetwork(nil, nil, true) error = %q, want missing config error", err)
	}
}

func TestCommissionNetworkMissingRequiredInputs(t *testing.T) {
	tests := []struct {
		name    string
		cfg     config.WiFiNetworkConfig
		wantErr string
	}{
		{
			name: "missing ssid",
			cfg: config.NewWiFiNetworkConfig(
				config.WithCredentials([]byte("passphrase")),
			),
			wantErr: "missing SSID",
		},
		{
			name: "missing credentials",
			cfg: config.NewWiFiNetworkConfig(
				config.WithSSID([]byte("ssid")),
			),
			wantErr: "missing credentials",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := commissionNetwork(nil, tt.cfg, true)
			if err == nil {
				t.Fatalf("commissionNetwork(nil, cfg, true) error = nil, want %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("commissionNetwork(nil, cfg, true) error = %q, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestCommissionOverPASEDoesNotInvokeCommissioningComplete(t *testing.T) {
	prevArmFailSafe := armFailSafeCommand
	prevAddTrustedRoot := addTrustedRootCertificateCommand
	prevAddNOC := addNOCCommand
	prevComplete := commissioningCompleteCommand
	t.Cleanup(func() {
		armFailSafeCommand = prevArmFailSafe
		addTrustedRootCertificateCommand = prevAddTrustedRoot
		addNOCCommand = prevAddNOC
		commissioningCompleteCommand = prevComplete
	})

	armFailSafeCommand = func(session.SecureSession, im.EndpointID, uint16, uint64) error { return nil }
	addTrustedRootCertificateCommand = func(session.SecureSession, im.EndpointID, []byte) error { return nil }
	addNOCCommand = func(session.SecureSession, im.EndpointID, []byte, []byte, []byte, uint64, uint16) error { return nil }

	calledCommissioningComplete := false
	commissioningCompleteCommand = func(session.SecureSession, im.EndpointID) error {
		calledCommissioningComplete = true
		return nil
	}

	err := commissionOverPASE(nil, validOperationalCredentialsConfig(), nil, false)
	if err != nil {
		t.Fatalf("commissionOverPASE(...) error = %v, want nil", err)
	}
	if calledCommissioningComplete {
		t.Fatal("commissionOverPASE(...) invoked CommissioningComplete, want false")
	}
}

func TestCommissionWithSessionReturnsExplicitNonConcurrentError(t *testing.T) {
	prevSupportsConcurrent := supportsConcurrentConnectionAttribute
	t.Cleanup(func() {
		supportsConcurrentConnectionAttribute = prevSupportsConcurrent
	})

	supportsConcurrentConnectionAttribute = func(session.SecureSession) (bool, error) {
		return false, nil
	}

	err := commissionWithSession(
		context.Background(),
		nil,
		nil,
		validOperationalCredentialsConfig(),
		nil,
		validAdministratorConfig(),
		false,
	)
	if err == nil {
		t.Fatal("commissionWithSession(...) error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "non-concurrent commissioning not yet supported") {
		t.Fatalf("commissionWithSession(...) error = %q, want non-concurrent error", err)
	}
}

func TestFinalizeCommissioningOverCASERequiresAdministratorConfig(t *testing.T) {
	err := finalizeCommissioningOverCASE(context.Background(), &stubDiscoverer{}, validOperationalCredentialsConfig(), nil)
	if err == nil {
		t.Fatal("finalizeCommissioningOverCASE(...) error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "administrator config is required") {
		t.Fatalf("finalizeCommissioningOverCASE(...) error = %q, want missing admin config error", err)
	}
}

func TestFinalizeCommissioningOverCASEPropagatesOperationalDiscoveryFailure(t *testing.T) {
	prevDiscoverOperational := operationalNodeDiscoverer
	prevEstablishCASE := establishOperationalCASESession
	t.Cleanup(func() {
		operationalNodeDiscoverer = prevDiscoverOperational
		establishOperationalCASESession = prevEstablishCASE
	})

	operationalNodeDiscoverer = func(context.Context, mdnspkg.Discoverer, operationalCASEPeer) (mdnspkg.CommissionableNode, error) {
		return nil, fmt.Errorf("operational discovery timeout")
	}
	establishOperationalCASESession = func(context.Context, mdnspkg.CommissionableNode, operationalCASEPeer, config.AdministratorConfig) (session.SecureSession, error) {
		t.Fatal("establishOperationalCASESession should not be called when discovery fails")
		return nil, nil
	}

	err := finalizeCommissioningOverCASE(context.Background(), &stubDiscoverer{}, validOperationalCredentialsConfig(), validAdministratorConfig())
	if err == nil {
		t.Fatal("finalizeCommissioningOverCASE(...) error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "operational discovery timeout") {
		t.Fatalf("finalizeCommissioningOverCASE(...) error = %q, want discovery timeout", err)
	}
}

type stubDiscoverer struct{}

func (*stubDiscoverer) Search(context.Context, mdnspkg.Query) ([]mdnspkg.CommissionableNode, error) {
	return nil, nil
}

func (*stubDiscoverer) Start() error { return nil }
func (*stubDiscoverer) Stop() error  { return nil }

func validOperationalCredentialsConfig() config.OperationalCredentialsConfig {
	rootDER, nocDER := testOperationalCredentialMaterials()
	return config.NewOperationalCredentialConfig(
		config.WithRootCertificate(rootDER),
		config.WithNOC(nocDER),
		config.WithIPK([]byte("0123456789abcdef")),
		config.WithCASEAdminNodeID(1),
		config.WithAdminVendorID(1),
	)
}

func validAdministratorConfig() config.AdministratorConfig {
	rootDER, _, adminNOCDER, adminKeyDER := testAdministratorMaterials()
	return config.NewAdministratorConfig(
		config.WithAdministratorNodeID(1),
		config.WithAdministratorFabricID(2),
		config.WithAdministratorRootCertificate(rootDER),
		config.WithAdministratorNOC(adminNOCDER),
		config.WithAdministratorPrivateKey(adminKeyDER),
	)
}

func testOperationalCredentialMaterials() ([]byte, []byte) {
	rootDER, rootTmpl, rootKey := testRootMaterials()
	nodeKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	nocTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(12),
		Subject: pkix.Name{
			CommonName: "Commissionee",
			ExtraNames: []pkix.AttributeTypeAndValue{
				{Type: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37244, 1, 1}, Value: "00000000000000AA"},
				{Type: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37244, 1, 5}, Value: "0000000000000002"},
			},
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	nocDER, _ := x509.CreateCertificate(rand.Reader, nocTmpl, rootTmpl, &nodeKey.PublicKey, rootKey)
	return rootDER, nocDER
}

func testAdministratorMaterials() ([]byte, []byte, []byte, []byte) {
	rootDER, rootTmpl, rootKey := testRootMaterials()
	adminKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	adminTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(22),
		Subject: pkix.Name{
			CommonName: "Administrator",
			ExtraNames: []pkix.AttributeTypeAndValue{
				{Type: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37244, 1, 1}, Value: "0000000000000001"},
				{Type: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37244, 1, 5}, Value: "0000000000000002"},
			},
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	adminNOCDER, _ := x509.CreateCertificate(rand.Reader, adminTmpl, rootTmpl, &adminKey.PublicKey, rootKey)
	adminKeyDER, _ := x509.MarshalPKCS8PrivateKey(adminKey)
	return rootDER, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}), adminNOCDER, adminKeyDER
}

func testRootMaterials() ([]byte, *x509.Certificate, *ecdsa.PrivateKey) {
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootDER)
	return rootDER, rootCert, rootKey
}
