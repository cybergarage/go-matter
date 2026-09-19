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

package mockdevice

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/cybergarage/go-matter/matter/config"
	caseprotocol "github.com/cybergarage/go-matter/matter/protocol/case"
	"github.com/cybergarage/go-matter/matter/protocol/session"
)

var (
	oidCASETestMatterNodeID   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37244, 1, 1}
	oidCASETestMatterFabricID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37244, 1, 5}
	oidCASETestExtKeyUsage    = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidCASETestServerAuth     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	oidCASETestClientAuth     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
)

func uint64ToHexRDN(v uint64) string {
	const hexDigits = "0123456789ABCDEF"
	b := make([]byte, 16)
	for i := 15; i >= 0; i-- {
		b[i] = hexDigits[v&0xF]
		v >>= 4
	}
	return string(b)
}

func caseTestClientServerAuthExtension(t *testing.T) pkix.Extension {
	t.Helper()
	val, err := asn1.Marshal([]asn1.ObjectIdentifier{oidCASETestClientAuth, oidCASETestServerAuth})
	if err != nil {
		t.Fatalf("marshal ExtKeyUsage: %v", err)
	}
	return pkix.Extension{Id: oidCASETestExtKeyUsage, Critical: true, Value: val}
}

// caseTestClientAuthOnlyExtension builds an ExtKeyUsage carrying only
// ClientAuth — missing the ServerAuth purpose connectedhomeip's CASESession
// requires on any NOC validated during CASE, initiator's or responder's
// (mValidContext.mRequiredKeyPurposes = kServerAuth). This project's own
// admin NOC template originally omitted ServerAuth (on the assumption a
// commissioner only ever needs to authenticate as CASE's initiator) and was
// rejected by a real device with exactly this symptom — see
// TestHandleCASERejectsInitiatorNOCMissingServerAuth below.
func caseTestClientAuthOnlyExtension(t *testing.T) pkix.Extension {
	t.Helper()
	val, err := asn1.Marshal([]asn1.ObjectIdentifier{oidCASETestClientAuth})
	if err != nil {
		t.Fatalf("marshal ExtKeyUsage: %v", err)
	}
	return pkix.Extension{Id: oidCASETestExtKeyUsage, Critical: true, Value: val}
}

// issueOperationalNOC builds an operational NOC (Matter NodeID/FabricID
// custom-OID Subject RDNs, both ClientAuth and ServerAuth ExtKeyUsage —
// see clusters_generalcommissioning.go's registration comment and this
// project's live-debugging history for why both purposes are required)
// signed by rootCert/rootKey, for either the admin or the mock device's own
// operational identity.
func issueOperationalNOC(t *testing.T, rootCert *x509.Certificate, rootKey *ecdsa.PrivateKey, fabricID, nodeID uint64) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	return issueOperationalNOCWithEKU(t, rootCert, rootKey, fabricID, nodeID, caseTestClientServerAuthExtension(t))
}

func issueOperationalNOCWithEKU(t *testing.T, rootCert *x509.Certificate, rootKey *ecdsa.PrivateKey, fabricID, nodeID uint64, eku pkix.Extension) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate NOC key: %v", err)
	}
	pubKeyBytes := elliptic.Marshal(key.PublicKey.Curve, key.PublicKey.X, key.PublicKey.Y)
	skid := sha1.Sum(pubKeyBytes) //nolint:gosec // RFC 5280 SubjectKeyId method 1 mandates SHA-1.
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(int64(nodeID)), //nolint:gosec // test-only, node IDs here are small
		Subject: pkix.Name{
			ExtraNames: []pkix.AttributeTypeAndValue{
				utf8Attr(oidCASETestMatterNodeID, uint64ToHexRDN(nodeID)),
				utf8Attr(oidCASETestMatterFabricID, uint64ToHexRDN(fabricID)),
			},
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtraExtensions:       []pkix.Extension{eku},
		BasicConstraintsValid: true,
		IsCA:                  false,
		SubjectKeyId:          skid[:],
		AuthorityKeyId:        rootCert.SubjectKeyId,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, rootCert, &key.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("issue NOC: %v", err)
	}
	return der, key
}

func utf8Attr(oid asn1.ObjectIdentifier, s string) pkix.AttributeTypeAndValue {
	return pkix.AttributeTypeAndValue{
		Type:  oid,
		Value: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagUTF8String, Bytes: []byte(s)},
	}
}

func TestHandleCASEInteropsWithRealInitiator(t *testing.T) {
	rootDER, _, rootKey := generateTestRootCA(t)
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("parse root certificate: %v", err)
	}

	const fabricID = 0x00000000AAAAAAAA
	const adminNodeID = 0x0000000000000001
	const deviceNodeID = 0x00000000DEADBEEF
	ipk := bytesOf(0x1A, 16)

	adminNOCDER, adminKey := issueOperationalNOC(t, rootCert, rootKey, fabricID, adminNodeID)
	adminKeyDER, err := x509.MarshalECPrivateKey(adminKey)
	if err != nil {
		t.Fatalf("marshal admin key: %v", err)
	}
	adminCfg := config.NewAdministratorConfig(
		config.WithAdministratorNodeID(adminNodeID),
		config.WithAdministratorFabricID(fabricID),
		config.WithAdministratorRootCertificate(rootDER),
		config.WithAdministratorNOC(adminNOCDER),
		config.WithAdministratorPrivateKey(adminKeyDER),
	)

	deviceNOCDER, deviceKey := issueOperationalNOC(t, rootCert, rootKey, fabricID, deviceNodeID)
	attestation, err := generateAttestationIdentity()
	if err != nil {
		t.Fatalf("generateAttestationIdentity() error = %v", err)
	}
	fs := newFabricState(attestation)
	fs.nocKey = deviceKey
	fs.rootCertDER = rootDER
	fs.nocDER = deviceNOCDER
	fs.rawIPK = ipk
	fs.caseAdminSubject = adminNodeID
	fs.nodeID = deviceNodeID
	fs.fabricID = fabricID

	initiatorTransport, deviceTransport := newPipeTransportPair()
	t.Cleanup(func() {
		_ = initiatorTransport.Close()
		_ = deviceTransport.Close()
	})

	deviceCtx, deviceCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer deviceCancel()
	type deviceResult struct {
		sess session.SecureSession
		err  error
	}
	deviceDone := make(chan deviceResult, 1)
	go func() {
		sess, err := handleCASE(deviceCtx, deviceTransport, fs)
		deviceDone <- deviceResult{sess: sess, err: err}
	}()

	initiator := caseprotocol.NewInitiator(initiatorTransport, adminCfg,
		caseprotocol.WithPeerNodeID(deviceNodeID),
		caseprotocol.WithIPK(ipk),
	)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	initiatorKeys, initiatorErr := initiator.EstablishSession(ctx)

	var deviceRes deviceResult
	select {
	case deviceRes = <-deviceDone:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for handleCASE to finish")
	}
	if initiatorErr != nil {
		t.Fatalf("initiator EstablishSession() error = %v (device error = %v)", initiatorErr, deviceRes.err)
	}
	if deviceRes.err != nil {
		t.Fatalf("handleCASE() error = %v", deviceRes.err)
	}

	// Prove the two independently-derived key sets actually interoperate —
	// not just that EstablishSession/handleCASE both returned without
	// error — by exchanging an AES-CCM-encrypted message in both
	// directions through session.SecureSession, exactly as
	// TestHandlePASEInteropsWithRealInitiator does for PASE.
	initiatorSess := session.NewSecureSession(initiatorTransport, initiatorKeys)
	deviceSess := deviceRes.sess

	type recvResult struct {
		b   []byte
		err error
	}
	recvDone := make(chan recvResult, 1)

	initiatorToDevice := []byte("hello from initiator (CASE)")
	go func() {
		b, err := deviceSess.Receive()
		recvDone <- recvResult{b, err}
	}()
	if err := initiatorSess.Transmit(initiatorToDevice); err != nil {
		t.Fatalf("initiator Transmit() error = %v", err)
	}
	recv1 := <-recvDone
	if recv1.err != nil {
		t.Fatalf("device Receive() error = %v", recv1.err)
	}
	if !bytes.Equal(recv1.b, initiatorToDevice) {
		t.Errorf("device received %q, want %q", recv1.b, initiatorToDevice)
	}

	deviceToInitiator := []byte("hello from device (CASE)")
	go func() {
		b, err := initiatorSess.Receive()
		recvDone <- recvResult{b, err}
	}()
	if err := deviceSess.Transmit(deviceToInitiator); err != nil {
		t.Fatalf("device Transmit() error = %v", err)
	}
	recv2 := <-recvDone
	if recv2.err != nil {
		t.Fatalf("initiator Receive() error = %v", recv2.err)
	}
	if !bytes.Equal(recv2.b, deviceToInitiator) {
		t.Errorf("initiator received %q, want %q", recv2.b, deviceToInitiator)
	}
}

// TestHandleCASERejectsInitiatorNOCMissingServerAuth guards against the
// exact regression fixed in mattertest/certs/certgen.go during this
// project's live-device debugging: a real device's CASE handler requires
// ServerAuth in ExtKeyUsage on any NOC it validates, initiator's or
// responder's, and rejected Sigma3 with StatusReport{FAILURE,
// INVALID_PARAMETER} when the admin's own NOC carried only ClientAuth. This
// test issues the initiator's NOC with exactly that same defect and
// confirms handleCASE's own chain validation (x509.Verify with Go's default
// KeyUsages, i.e. ExtKeyUsageServerAuth) independently catches it too.
func TestHandleCASERejectsInitiatorNOCMissingServerAuth(t *testing.T) {
	rootDER, _, rootKey := generateTestRootCA(t)
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("parse root certificate: %v", err)
	}

	const fabricID = 0x00000000AAAAAAAA
	const adminNodeID = 0x0000000000000001
	const deviceNodeID = 0x00000000DEADBEEF
	ipk := bytesOf(0x1A, 16)

	adminNOCDER, adminKey := issueOperationalNOCWithEKU(t, rootCert, rootKey, fabricID, adminNodeID, caseTestClientAuthOnlyExtension(t))
	adminKeyDER, err := x509.MarshalECPrivateKey(adminKey)
	if err != nil {
		t.Fatalf("marshal admin key: %v", err)
	}
	adminCfg := config.NewAdministratorConfig(
		config.WithAdministratorNodeID(adminNodeID),
		config.WithAdministratorFabricID(fabricID),
		config.WithAdministratorRootCertificate(rootDER),
		config.WithAdministratorNOC(adminNOCDER),
		config.WithAdministratorPrivateKey(adminKeyDER),
	)

	deviceNOCDER, deviceKey := issueOperationalNOC(t, rootCert, rootKey, fabricID, deviceNodeID)
	attestation, err := generateAttestationIdentity()
	if err != nil {
		t.Fatalf("generateAttestationIdentity() error = %v", err)
	}
	fs := newFabricState(attestation)
	fs.nocKey = deviceKey
	fs.rootCertDER = rootDER
	fs.nocDER = deviceNOCDER
	fs.rawIPK = ipk
	fs.caseAdminSubject = adminNodeID
	fs.nodeID = deviceNodeID
	fs.fabricID = fabricID

	initiatorTransport, deviceTransport := newPipeTransportPair()
	t.Cleanup(func() {
		_ = initiatorTransport.Close()
		_ = deviceTransport.Close()
	})

	deviceCtx, deviceCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer deviceCancel()
	type deviceResult struct {
		sess session.SecureSession
		err  error
	}
	deviceDone := make(chan deviceResult, 1)
	go func() {
		sess, err := handleCASE(deviceCtx, deviceTransport, fs)
		deviceDone <- deviceResult{sess: sess, err: err}
	}()

	initiator := caseprotocol.NewInitiator(initiatorTransport, adminCfg,
		caseprotocol.WithPeerNodeID(deviceNodeID),
		caseprotocol.WithIPK(ipk),
	)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, initiatorErr := initiator.EstablishSession(ctx)
	if initiatorErr == nil {
		t.Fatal("initiator EstablishSession() error = nil, want a StatusReport rejection")
	}

	var deviceRes deviceResult
	select {
	case deviceRes = <-deviceDone:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for handleCASE to finish")
	}
	if deviceRes.err == nil {
		t.Error("handleCASE() error = nil, want a certificate chain validation failure")
	}
}
