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
	"bytes"
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
	mcrypto "github.com/cybergarage/go-matter/matter/crypto"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	mdnspkg "github.com/cybergarage/go-matter/matter/mdns"
	caseprotocol "github.com/cybergarage/go-matter/matter/protocol/case"
	"github.com/cybergarage/go-matter/matter/protocol/im"
	"github.com/cybergarage/go-matter/matter/protocol/session"
)

func TestCommissionOperationalCredentialsNilConfig(t *testing.T) {
	_, err := commissionOperationalCredentials(nil, nil, nil, deviceAttestationResult{})
	if err == nil {
		t.Fatal("commissionOperationalCredentials(...) error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "operational credentials config is required") {
		t.Fatalf("commissionOperationalCredentials(...) error = %q, want missing config error", err)
	}
}

func TestCommissionOperationalCredentialsMissingRequiredInputs(t *testing.T) {
	tests := []struct {
		name    string
		cfg     config.OperationalCredentialsConfig
		wantErr string
	}{
		{
			name: "missing ipk",
			cfg: config.NewOperationalCredentialConfig(
				config.WithCASEAdminNodeID(1),
				config.WithAdminVendorID(1),
			),
			wantErr: "missing IPK",
		},
		{
			name: "missing case admin node id",
			cfg: config.NewOperationalCredentialConfig(
				config.WithIPK([]byte{0x03}),
				config.WithAdminVendorID(1),
			),
			wantErr: "missing CASE admin node ID",
		},
		{
			name: "missing admin vendor id",
			cfg: config.NewOperationalCredentialConfig(
				config.WithIPK([]byte{0x03}),
				config.WithCASEAdminNodeID(1),
			),
			wantErr: "missing admin vendor ID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := commissionOperationalCredentials(nil, tt.cfg, nil, deviceAttestationResult{})
			if err == nil {
				t.Fatalf("commissionOperationalCredentials(...) error = nil, want %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("commissionOperationalCredentials(...) error = %q, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestCommissionOperationalCredentialsIssuesNOCAndInstallsIt(t *testing.T) {
	prevAddTrustedRoot := addTrustedRootCertificateCommand
	prevAddNOC := addNOCCommand
	t.Cleanup(func() {
		addTrustedRootCertificateCommand = prevAddTrustedRoot
		addNOCCommand = prevAddNOC
	})

	var gotRootDER, gotNOCDER []byte
	var gotIPK []byte
	var gotCASEAdminSubject uint64
	var gotAdminVendorID uint16
	addTrustedRootCertificateCommand = func(_ session.SecureSession, _ im.EndpointID, rootCertDER []byte) error {
		gotRootDER = rootCertDER
		return nil
	}
	addNOCCommand = func(_ session.SecureSession, _ im.EndpointID, nocDER, icacDER, ipk []byte, caseAdminSubject uint64, adminVendorID uint16) error {
		gotNOCDER = nocDER
		gotIPK = ipk
		gotCASEAdminSubject = caseAdminSubject
		gotAdminVendorID = adminVendorID
		return nil
	}

	adminCfg := validAdministratorConfig()
	opCfg := validOperationalCredentialsConfig()
	csr := generateTestCSR(t)

	identity, err := commissionOperationalCredentials(stubSecureSession{}, opCfg, adminCfg, deviceAttestationResult{csr: csr})
	if err != nil {
		t.Fatalf("commissionOperationalCredentials(...) error = %v, want nil", err)
	}
	if identity.nodeID == 0 {
		t.Error("identity.nodeID = 0, want a non-zero assigned node ID")
	}
	if len(gotRootDER) == 0 {
		t.Error("AddTrustedRootCertificate was not called with a root certificate")
	}
	if len(gotNOCDER) == 0 || !bytes.Equal(gotNOCDER, identity.noc) {
		t.Error("AddNOC was not called with the issued NOC")
	}
	if string(gotIPK) != "0123456789abcdef" {
		t.Errorf("AddNOC IPK = %q, want %q", gotIPK, "0123456789abcdef")
	}
	if gotCASEAdminSubject != 1 || gotAdminVendorID != 1 {
		t.Errorf("AddNOC(caseAdminSubject=%d, adminVendorID=%d), want (1, 1)", gotCASEAdminSubject, gotAdminVendorID)
	}

	nocCert, err := x509.ParseCertificate(gotNOCDER)
	if err != nil {
		t.Fatalf("parse issued NOC: %v", err)
	}
	if !nocCert.PublicKey.(*ecdsa.PublicKey).Equal(csr.PublicKey.(*ecdsa.PublicKey)) {
		t.Error("issued NOC public key does not match the device's CSR public key")
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
	prevAttestationFn := commissionDeviceAttestationFn
	prevAddTrustedRoot := addTrustedRootCertificateCommand
	prevAddNOC := addNOCCommand
	prevComplete := commissioningCompleteCommand
	t.Cleanup(func() {
		armFailSafeCommand = prevArmFailSafe
		commissionDeviceAttestationFn = prevAttestationFn
		addTrustedRootCertificateCommand = prevAddTrustedRoot
		addNOCCommand = prevAddNOC
		commissioningCompleteCommand = prevComplete
	})

	armFailSafeCommand = func(session.SecureSession, im.EndpointID, uint16, uint64) error { return nil }
	commissionDeviceAttestationFn = func(session.SecureSession) (deviceAttestationResult, error) {
		return deviceAttestationResult{csr: generateTestCSR(t)}, nil
	}
	addTrustedRootCertificateCommand = func(session.SecureSession, im.EndpointID, []byte) error { return nil }
	addNOCCommand = func(session.SecureSession, im.EndpointID, []byte, []byte, []byte, uint64, uint16) error { return nil }

	calledCommissioningComplete := false
	commissioningCompleteCommand = func(session.SecureSession, im.EndpointID) error {
		calledCommissioningComplete = true
		return nil
	}

	_, err := commissionOverPASE(nil, validOperationalCredentialsConfig(), validAdministratorConfig(), nil, false)
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

	_, err := commissionWithSession(
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
	err := finalizeCommissioningOverCASE(context.Background(), &stubDiscoverer{}, validOperationalCredentialsConfig(), nil, deviceOperationalIdentity{nodeID: 1}, nil)
	if err == nil {
		t.Fatal("finalizeCommissioningOverCASE(...) error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "administrator config is required") {
		t.Fatalf("finalizeCommissioningOverCASE(...) error = %q, want missing admin config error", err)
	}
}

// TestDiscoverOperationalNodeBoundsSearchContext guards against a real
// regression: discoverOperationalNode passed the single ctx spanning the
// entire PASE-through-CASE commissioning exchange straight through to
// mdns.Discoverer.Search. Since that ctx already has a (long) deadline,
// Search's own short-default-timeout fallback never kicks in (it only
// applies when the given ctx has no deadline at all), so the underlying
// mDNS query blocked collecting responses for however much of the overall
// commissioning budget was left — observed on a real device taking well
// over 100s to return even though the matching operational record had
// already been seen within about a second.
func TestDiscoverOperationalNodeBoundsSearchContext(t *testing.T) {
	var gotDeadline time.Time
	var gotOK bool
	disc := &capturingDiscoverer{
		searchFunc: func(ctx context.Context, _ mdnspkg.Query) ([]mdnspkg.CommissionableNode, error) {
			gotDeadline, gotOK = ctx.Deadline()
			return nil, nil
		},
	}

	// A long-lived outer deadline, standing in for
	// DefaultCommissioningTimeout's 120s span.
	outerCtx, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()

	before := time.Now()
	_, _ = discoverOperationalNode(outerCtx, disc, operationalCASEPeer{serviceInstance: "test"})

	if !gotOK {
		t.Fatal("discoverOperationalNode passed Search a context with no deadline, want one bounded to DefaultDiscoveryTimeout")
	}
	maxExpected := before.Add(DefaultDiscoveryTimeout + time.Second)
	if gotDeadline.After(maxExpected) {
		t.Errorf("Search context deadline = %s, want within DefaultDiscoveryTimeout (%s) of now, not the outer ctx's ~1h deadline",
			gotDeadline, DefaultDiscoveryTimeout)
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
	establishOperationalCASESession = func(context.Context, mdnspkg.CommissionableNode, operationalCASEPeer, config.AdministratorConfig, caseprotocol.Transport) (session.SecureSession, error) {
		t.Fatal("establishOperationalCASESession should not be called when discovery fails")
		return nil, nil
	}

	err := finalizeCommissioningOverCASE(context.Background(), &stubDiscoverer{}, validOperationalCredentialsConfig(), validAdministratorConfig(), deviceOperationalIdentity{nodeID: 1}, nil)
	if err == nil {
		t.Fatal("finalizeCommissioningOverCASE(...) error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "operational discovery timeout") {
		t.Fatalf("finalizeCommissioningOverCASE(...) error = %q, want discovery timeout", err)
	}
}

func TestCommissionDeviceAttestationVerifiesSignaturesAndParsesCSR(t *testing.T) {
	prevAttestationReq := attestationRequestCommand
	prevCertChainReq := certificateChainRequestCommand
	prevCSRReq := csrRequestCommand
	t.Cleanup(func() {
		attestationRequestCommand = prevAttestationReq
		certificateChainRequestCommand = prevCertChainReq
		csrRequestCommand = prevCSRReq
	})

	fixture := newDeviceAttestationFixture(t)
	attestationRequestCommand = fixture.attestationRequestCommand
	certificateChainRequestCommand = fixture.certificateChainRequestCommand
	csrRequestCommand = fixture.csrRequestCommand

	result, err := commissionDeviceAttestation(stubSecureSession{})
	if err != nil {
		t.Fatalf("commissionDeviceAttestation(...) error = %v, want nil", err)
	}
	if !result.dacPubKey.Equal(&fixture.dacKey.PublicKey) {
		t.Error("commissionDeviceAttestation(...) dacPubKey does not match the fixture's DAC key")
	}
	if !result.csr.PublicKey.(*ecdsa.PublicKey).Equal(fixture.deviceCSR.PublicKey.(*ecdsa.PublicKey)) {
		t.Error("commissionDeviceAttestation(...) csr does not match the fixture's device CSR")
	}
}

func TestCommissionDeviceAttestationRejectsTamperedSignature(t *testing.T) {
	prevAttestationReq := attestationRequestCommand
	prevCertChainReq := certificateChainRequestCommand
	prevCSRReq := csrRequestCommand
	t.Cleanup(func() {
		attestationRequestCommand = prevAttestationReq
		certificateChainRequestCommand = prevCertChainReq
		csrRequestCommand = prevCSRReq
	})

	fixture := newDeviceAttestationFixture(t)
	// Sign the attestation elements with a different (untrusted) key than the
	// one presented as the DAC, simulating a device that isn't the holder of
	// the DAC private key.
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fixture.attestationSig = signRaw(t, otherKey, append(append([]byte{}, fixture.attestationElementsTLV...), fixture.challenge...))

	attestationRequestCommand = fixture.attestationRequestCommand
	certificateChainRequestCommand = fixture.certificateChainRequestCommand
	csrRequestCommand = fixture.csrRequestCommand

	if _, err := commissionDeviceAttestation(stubSecureSession{}); err == nil {
		t.Fatal("commissionDeviceAttestation(...) error = nil, want signature verification failure")
	}
}

type stubDiscoverer struct{}

func (*stubDiscoverer) Search(context.Context, mdnspkg.Query) ([]mdnspkg.CommissionableNode, error) {
	return nil, nil
}

// capturingDiscoverer lets a test inspect exactly what ctx/query
// discoverOperationalNode passes to mdns.Discoverer.Search.
type capturingDiscoverer struct {
	searchFunc func(context.Context, mdnspkg.Query) ([]mdnspkg.CommissionableNode, error)
}

func (d *capturingDiscoverer) Search(ctx context.Context, q mdnspkg.Query) ([]mdnspkg.CommissionableNode, error) {
	return d.searchFunc(ctx, q)
}

func (*capturingDiscoverer) Start() error { return nil }
func (*capturingDiscoverer) Stop() error  { return nil }

func (*stubDiscoverer) Start() error { return nil }
func (*stubDiscoverer) Stop() error  { return nil }

// stubSecureSession is a minimal session.SecureSession for tests that only
// need a working SessionKeys().AttestationChallenge(); Transmit/Receive are
// never expected to be called because all cluster-command network I/O is
// routed through this package's swappable function vars in tests.
type stubSecureSession struct{}

func (stubSecureSession) Transmit([]byte) error {
	return fmt.Errorf("stubSecureSession: Transmit unexpectedly called")
}
func (stubSecureSession) Receive() ([]byte, error) {
	return nil, fmt.Errorf("stubSecureSession: Receive unexpectedly called")
}
func (stubSecureSession) Transport() session.Transport     { return nil }
func (stubSecureSession) SessionKeys() session.SessionKeys { return stubSessionKeys{} }

type stubSessionKeys struct{}

func (stubSessionKeys) I2RKey() []byte                        { return nil }
func (stubSessionKeys) R2IKey() []byte                        { return nil }
func (stubSessionKeys) InitiatorSessionID() session.SessionID { return 0 }
func (stubSessionKeys) ResponderSessionID() session.SessionID { return 0 }
func (stubSessionKeys) LocalNodeID() session.NodeID           { return 0 }
func (stubSessionKeys) PeerNodeID() session.NodeID            { return 0 }
func (stubSessionKeys) AttestationChallenge() []byte          { return bytes.Repeat([]byte{0x5A}, 16) }

// deviceAttestationFixture provides fake but cryptographically valid
// AttestationRequest/CertificateChainRequest/CSRRequest responses, signed by
// a locally generated "DAC" key, for exercising commissionDeviceAttestation's
// real verification logic without a real device or wire transport.
type deviceAttestationFixture struct {
	dacKey    *ecdsa.PrivateKey
	dacDER    []byte
	deviceCSR *x509.CertificateRequest
	challenge []byte

	attestationElementsTLV []byte
	attestationSig         []byte
	nocsrElementsTLV       []byte
	csrSig                 []byte
}

func newDeviceAttestationFixture(t *testing.T) *deviceAttestationFixture {
	t.Helper()
	dacKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	dacTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test DAC"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	dacDER, err := x509.CreateCertificate(rand.Reader, dacTmpl, dacTmpl, &dacKey.PublicKey, dacKey)
	if err != nil {
		t.Fatal(err)
	}

	f := &deviceAttestationFixture{
		dacKey:    dacKey,
		dacDER:    dacDER,
		deviceCSR: generateTestCSR(t),
		challenge: bytes.Repeat([]byte{0x5A}, 16), // matches stubSessionKeys.AttestationChallenge
	}

	f.attestationElementsTLV = encodeAttestationElementsTLV(t, []byte{0x01, 0x02}, bytes.Repeat([]byte{0x11}, attestationNonceLength), 1000)
	f.attestationSig = signRaw(t, dacKey, append(append([]byte{}, f.attestationElementsTLV...), f.challenge...))

	f.nocsrElementsTLV = encodeNOCSRElementsTLV(t, f.deviceCSR.Raw, bytes.Repeat([]byte{0x22}, csrNonceLength))
	f.csrSig = signRaw(t, dacKey, append(append([]byte{}, f.nocsrElementsTLV...), f.challenge...))

	return f
}

func (f *deviceAttestationFixture) attestationRequestCommand(session.SecureSession, im.EndpointID, []byte) ([]byte, []byte, error) {
	return f.attestationElementsTLV, f.attestationSig, nil
}

func (f *deviceAttestationFixture) certificateChainRequestCommand(_ session.SecureSession, _ im.EndpointID, certType uint8) ([]byte, error) {
	if certType == certificateTypePAI {
		return f.dacDER, nil // reuse the DAC cert as a stand-in PAI; not validated.
	}
	return f.dacDER, nil
}

func (f *deviceAttestationFixture) csrRequestCommand(session.SecureSession, im.EndpointID, []byte) ([]byte, []byte, error) {
	return f.nocsrElementsTLV, f.csrSig, nil
}

func encodeAttestationElementsTLV(t *testing.T, cd, nonce []byte, timestamp uint32) []byte {
	t.Helper()
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	if err := enc.PutOctet(tlv.NewContextTag(1), cd); err != nil {
		t.Fatal(err)
	}
	if err := enc.PutOctet(tlv.NewContextTag(2), nonce); err != nil {
		t.Fatal(err)
	}
	enc.PutUnsigned4(tlv.NewContextTag(3), timestamp)
	if err := enc.EndContainer(); err != nil {
		t.Fatal(err)
	}
	return enc.Bytes()
}

func encodeNOCSRElementsTLV(t *testing.T, csrDER, csrNonce []byte) []byte {
	t.Helper()
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	if err := enc.PutOctet(tlv.NewContextTag(1), csrDER); err != nil {
		t.Fatal(err)
	}
	if err := enc.PutOctet(tlv.NewContextTag(2), csrNonce); err != nil {
		t.Fatal(err)
	}
	if err := enc.EndContainer(); err != nil {
		t.Fatal(err)
	}
	return enc.Bytes()
}

func signRaw(t *testing.T, key *ecdsa.PrivateKey, msg []byte) []byte {
	t.Helper()
	sig, err := mcrypto.CryptoSign(mcrypto.NewPrivateKey(key), msg)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, 64)
	copy(out[32-len(sig.R()):32], sig.R())
	copy(out[64-len(sig.S()):64], sig.S())
	return out
}

func generateTestCSR(t *testing.T) *x509.CertificateRequest {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

func validOperationalCredentialsConfig() config.OperationalCredentialsConfig {
	return config.NewOperationalCredentialConfig(
		config.WithIPK([]byte("0123456789abcdef")),
		config.WithCASEAdminNodeID(1),
		config.WithAdminVendorID(1),
	)
}

func validAdministratorConfig() config.AdministratorConfig {
	rootDER, rootPEM, rootKeyPEM, adminNOCDER, adminKeyDER := testAdministratorMaterials()
	_ = rootDER
	return config.NewAdministratorConfig(
		config.WithAdministratorNodeID(1),
		config.WithAdministratorFabricID(2),
		config.WithAdministratorRootCertificate(rootPEM),
		config.WithAdministratorRootPrivateKey(rootKeyPEM),
		config.WithAdministratorNOC(adminNOCDER),
		config.WithAdministratorPrivateKey(adminKeyDER),
	)
}

// Returns (rootDER, rootPEM, rootKeyPEM, adminNOCDER, adminKeyDER).
func testAdministratorMaterials() ([]byte, []byte, []byte, []byte, []byte) {
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
	rootKeyDER, _ := x509.MarshalECPrivateKey(rootKey)
	rootKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: rootKeyDER})
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
	return rootDER, rootPEM, rootKeyPEM, adminNOCDER, adminKeyDER
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
