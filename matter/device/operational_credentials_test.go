// Copyright (C) 2026 The go-matter Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package device

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

	"github.com/cybergarage/go-matter/matter/cluster/generalcommissioning"
	"github.com/cybergarage/go-matter/matter/cluster/operationalcredentials"
	"github.com/cybergarage/go-matter/matter/config"
	"github.com/cybergarage/go-matter/matter/credentials"
	"github.com/cybergarage/go-matter/matter/credentials/chipcert"
	"github.com/cybergarage/go-matter/matter/credentials/testcreds"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	caseprotocol "github.com/cybergarage/go-matter/matter/protocol/case"
	"github.com/cybergarage/go-matter/matter/protocol/im"
	"github.com/cybergarage/go-matter/matter/protocol/pase"
	"github.com/cybergarage/go-matter/matter/protocol/session"
	"github.com/cybergarage/go-matter/matter/store"
)

const (
	testFabricID         uint64 = 0x2906C908D115D362
	testAdminNodeID      uint64 = 0x0000000000000001
	testAdminVendorID    uint16 = 0xFFF1
	testCommissioneeNode uint64 = 0x00000000DEADBEEF
)

var testIPK = []byte("0123456789abcdef")

// testCA is a commissioner's fabric root: a Matter RCAC and the CA which
// issues NOCs under it.
type testCA struct {
	fabricID   uint64
	rootDER    []byte
	rootKeyDER []byte
	ca         *credentials.CertificateAuthority
}

func newTestCA(t *testing.T, fabricID uint64) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := key.PublicKey.ECDH()
	if err != nil {
		t.Fatal(err)
	}
	skid := sha1.Sum(pub.Bytes())
	rcacID := pkix.AttributeTypeAndValue{
		Type:  asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37244, 1, 4},
		Value: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagUTF8String, Bytes: []byte("0000000000000001")},
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{ExtraNames: []pkix.AttributeTypeAndValue{rcacID}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          skid[:],
		AuthorityKeyId:        skid[:],
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := credentials.NewCertificateAuthority(rootDER, keyDER, fabricID)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{fabricID: fabricID, rootDER: rootDER, rootKeyDER: keyDER, ca: ca}
}

// admin returns the configuration of an administrator on the CA's fabric,
// with a NOC for nodeID, as a commissioner initiates CASE with.
func (c *testCA) admin(t *testing.T, nodeID uint64) config.AdministratorConfig {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := credentials.NewSoftwareSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := credentials.CreateCSR(signer)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := credentials.ParseCSR(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	nocDER, err := c.ca.IssueNOC(csr, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return config.NewAdministratorConfig(
		config.WithAdministratorNodeID(nodeID),
		config.WithAdministratorFabricID(c.fabricID),
		config.WithAdministratorRootCertificate(c.rootDER),
		config.WithAdministratorRootPrivateKey(c.rootKeyDER),
		config.WithAdministratorNOC(nocDER),
		config.WithAdministratorPrivateKey(keyDER),
	)
}

func (c *testCA) rootTLV(t *testing.T) []byte {
	t.Helper()
	b, err := chipcert.DERToTLV(c.rootDER)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// issue returns a NOC, in the Matter TLV encoding, for the key of a PKCS#10
// CSR.
func (c *testCA) issue(t *testing.T, csrDER []byte, nodeID uint64) []byte {
	t.Helper()
	csr, err := credentials.ParseCSR(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	nocDER, err := c.ca.IssueNOC(csr, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	b, err := chipcert.DERToTLV(nocDER)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func testAttestationProvider(t *testing.T) credentials.AttestationProvider {
	t.Helper()
	p, err := testcreds.AttestationProvider()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// startCommissioning starts a device with the test attestation
// credentials and returns a commissioner's PASE session with it.
func startCommissioning(t *testing.T) (*Device, session.SecureSession) {
	t.Helper()
	d, sess, _ := startCommissioningWithClient(t)
	return d, sess
}

// startCommissioningWithClient is startCommissioning which also returns
// the commissioner's UDP transport, to go on to CASE over.
func startCommissioningWithClient(t *testing.T) (*Device, session.SecureSession, *udpClient) {
	t.Helper()
	d, _, _ := startTestDevice(t, WithAttestationProvider(testAttestationProvider(t)))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := dialDevice(t, d)
	keys, err := pase.NewInitiator(client, testPasscode).EstablishSession(ctx)
	if err != nil {
		t.Fatalf("PASE: %v", err)
	}
	return d, session.NewSecureSession(client, keys), client
}

func randomNonce(t *testing.T) []byte {
	t.Helper()
	nonce := make([]byte, attestationNonceLength)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	return nonce
}

// readStructList reads a list attribute of structs, each as its fields by
// context tag.
func readStructList(t *testing.T, sess session.SecureSession, attr im.AttributeID) []map[uint8]tlv.Element {
	t.Helper()
	var items []map[uint8]tlv.Element
	status, err := im.ReadListAttribute(sess, 0, OperationalCredentialsClusterID, attr, func(dec tlv.Decoder, item tlv.Element) error {
		fields := map[uint8]tlv.Element{}
		if item.Type().IsStructure() {
			for dec.Next() {
				elem := dec.Element()
				if elem.Type().IsEndOfContainer() {
					break
				}
				if ct, ok := elem.Tag().(tlv.ContextTag); ok {
					fields[uint8(ct.ContextNumber())] = elem
				}
			}
		} else {
			fields[0] = item
		}
		items = append(items, fields)
		return dec.Error()
	})
	if err != nil || status != nil {
		t.Fatalf("read attribute 0x%04X: (%+v, %v)", attr, status, err)
	}
	return items
}

func readUint8(t *testing.T, sess session.SecureSession, attr im.AttributeID) uint64 {
	t.Helper()
	resp, err := im.ReadAttribute(sess, 0, OperationalCredentialsClusterID, attr)
	if err != nil || resp.Status != nil {
		t.Fatalf("read attribute 0x%04X: (%+v, %v)", attr, resp, err)
	}
	v, _ := resp.Value.Unsigned()
	return v
}

// TestDeviceOperationalCredentialsOverPASE commissions the device over UDP
// up to AddNOC with go-matter's own Operational Credentials client, as a
// commissioner does before CASE: attestation, CSR, root and NOC. The
// fabric is visible while the fail-safe is armed, and disarming it rolls
// the fabric back.
func TestDeviceOperationalCredentialsOverPASE(t *testing.T) {
	d, sess := startCommissioning(t)
	challenge := sess.SessionKeys().AttestationChallenge()

	// Commissioning changes need the fail-safe.
	resp, err := im.Invoke(sess, 0, OperationalCredentialsClusterID, csrRequestCommandID, csrRequestFields(t, randomNonce(t)))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status.IMStatus != uint8(im.StatusFailsafeRequired) {
		t.Fatalf("CSRRequest without a fail-safe: status %#x, want FailsafeRequired", resp.Status.IMStatus)
	}
	if err := generalcommissioning.ArmFailSafe(sess, 0, 60, 1); err != nil {
		t.Fatal(err)
	}

	// Attestation: the elements are signed by the DAC the device returns,
	// which chains to the test PAA through the PAI.
	nonce := randomNonce(t)
	elements, sig, err := operationalcredentials.AttestationRequest(sess, 0, nonce)
	if err != nil {
		t.Fatal(err)
	}
	dacDER, err := operationalcredentials.CertificateChainRequest(sess, 0, uint8(CertificateChainDAC))
	if err != nil {
		t.Fatal(err)
	}
	paiDER, err := operationalcredentials.CertificateChainRequest(sess, 0, uint8(CertificateChainPAI))
	if err != nil {
		t.Fatal(err)
	}
	dac, err := x509.ParseCertificate(dacDER)
	if err != nil {
		t.Fatal(err)
	}
	pai, err := x509.ParseCertificate(paiDER)
	if err != nil {
		t.Fatal(err)
	}
	if err := dac.CheckSignatureFrom(pai); err != nil {
		t.Fatalf("the DAC is not issued by the PAI: %v", err)
	}
	dacPub, _ := dac.PublicKey.(*ecdsa.PublicKey)
	if err := credentials.VerifyAttestationSignature(elements, challenge, sig, dacPub); err != nil {
		t.Fatal(err)
	}
	parsed, err := credentials.ParseAttestationElements(elements)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsed.Nonce, nonce) {
		t.Fatal("AttestationElements does not carry the nonce")
	}

	// CSR, signed by the DAC.
	csrNonce := randomNonce(t)
	nocsr, csrSig, err := operationalcredentials.CSRRequest(sess, 0, csrNonce)
	if err != nil {
		t.Fatal(err)
	}
	if err := credentials.VerifyNOCSRElementsSignature(nocsr, challenge, csrSig, dacPub); err != nil {
		t.Fatal(err)
	}
	csrElements, err := credentials.ParseNOCSRElements(nocsr)
	if err != nil {
		t.Fatal(err)
	}

	// Root and NOC.
	ca := newTestCA(t, testFabricID)
	csr, err := credentials.ParseCSR(csrElements.CSR)
	if err != nil {
		t.Fatal(err)
	}
	nocDER, err := ca.ca.IssueNOC(csr, testCommissioneeNode)
	if err != nil {
		t.Fatal(err)
	}
	if err := operationalcredentials.AddTrustedRootCertificate(sess, 0, ca.rootDER); err != nil {
		t.Fatal(err)
	}
	if err := operationalcredentials.AddNOC(sess, 0, nocDER, nil, testIPK, testAdminNodeID, testAdminVendorID); err != nil {
		t.Fatal(err)
	}

	// The staged fabric is reported while the fail-safe is armed.
	if n := readUint8(t, sess, commissionedFabricsAttributeID); n != 1 {
		t.Fatalf("CommissionedFabrics = %d, want 1", n)
	}
	if n := readUint8(t, sess, supportedFabricsAttributeID); n != DefaultSupportedFabrics {
		t.Fatalf("SupportedFabrics = %d, want %d", n, DefaultSupportedFabrics)
	}
	fabrics := readStructList(t, sess, fabricsAttributeID)
	if len(fabrics) != 1 {
		t.Fatalf("Fabrics has %d entries, want 1", len(fabrics))
	}
	if v, _ := fabrics[0][3].Unsigned(); v != testFabricID {
		t.Errorf("Fabrics[0].FabricID = 0x%X, want 0x%X", v, testFabricID)
	}
	if v, _ := fabrics[0][4].Unsigned(); v != testCommissioneeNode {
		t.Errorf("Fabrics[0].NodeID = 0x%X, want 0x%X", v, testCommissioneeNode)
	}
	if v, _ := fabrics[0][2].Unsigned(); v != uint64(testAdminVendorID) {
		t.Errorf("Fabrics[0].VendorID = 0x%X, want 0x%X", v, testAdminVendorID)
	}
	if v, _ := fabrics[0][fabricIndexTag].Unsigned(); v != 1 {
		t.Errorf("Fabrics[0].FabricIndex = %d, want 1", v)
	}
	nocs := readStructList(t, sess, nocsAttributeID)
	if len(nocs) != 1 {
		t.Fatalf("NOCs has %d entries, want 1", len(nocs))
	}
	if b, _ := nocs[0][1].Bytes(); !bytes.Equal(b, ca.issueTLV(t, nocDER)) {
		t.Error("NOCs[0].NOC is not the NOC AddNOC installed")
	}
	roots := readStructList(t, sess, trustedRootCertificatesAttributeID)
	if len(roots) != 1 {
		t.Fatalf("TrustedRootCertificates has %d entries, want 1", len(roots))
	}
	if b, _ := roots[0][0].Bytes(); !bytes.Equal(b, ca.rootTLV(t)) {
		t.Error("TrustedRootCertificates[0] is not the root AddTrustedRootCertificate installed")
	}

	// The fabric, its ACL and IPK are written through the fail-safe's
	// transaction, not to the store.
	tx, _ := d.failSafe.armedTransaction()
	acl, err := tx.LoadACL(1)
	if err != nil || len(acl) != 1 || acl[0].Privilege != store.PrivilegeAdminister || acl[0].AuthMode != store.AuthModeCASE || len(acl[0].Subjects) != 1 || acl[0].Subjects[0] != testAdminNodeID {
		t.Fatalf("ACL of fabric 1 = (%+v, %v), want Administer over CASE for the admin", acl, err)
	}
	keys, err := tx.LoadGroupKeys(1)
	if err != nil || len(keys.KeySets) != 1 || !bytes.Equal(keys.KeySets[0].EpochKeys[0].Key, testIPK) {
		t.Fatalf("group keys of fabric 1 = (%+v, %v), want the IPK as key set 0", keys, err)
	}
	if committed, err := d.store.ListDeviceFabrics(); err != nil || len(committed) != 0 {
		t.Fatalf("the store holds %d fabrics before CommissioningComplete (%v)", len(committed), err)
	}

	// A second AddNOC under the same fail-safe is refused.
	err = operationalcredentials.AddNOC(sess, 0, nocDER, nil, testIPK, testAdminNodeID, testAdminVendorID)
	if err == nil {
		t.Fatal("a second AddNOC succeeded")
	}

	// Disarming the fail-safe rolls the fabric back.
	if err := generalcommissioning.ArmFailSafe(sess, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	if n := readUint8(t, sess, commissionedFabricsAttributeID); n != 0 {
		t.Fatalf("CommissionedFabrics = %d after disarming, want 0", n)
	}
	if roots := readStructList(t, sess, trustedRootCertificatesAttributeID); len(roots) != 0 {
		t.Fatalf("TrustedRootCertificates has %d entries after disarming, want 0", len(roots))
	}
}

func (c *testCA) issueTLV(t *testing.T, der []byte) []byte {
	t.Helper()
	b, err := chipcert.DERToTLV(der)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func csrRequestFields(t *testing.T, nonce []byte) []byte {
	t.Helper()
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewContextTag(1))
	if err := enc.PutOctet(tlv.NewContextTag(0), nonce); err != nil {
		t.Fatal(err)
	}
	if err := enc.EndContainer(); err != nil {
		t.Fatal(err)
	}
	return enc.Bytes()
}

func newAddNOCRequest(t *testing.T, noc []byte, subject uint64, ipk []byte) *im.CommandRequest {
	t.Helper()
	return &im.CommandRequest{Fields: commandFields(t, func(enc tlv.Encoder) {
		_ = enc.PutOctet(tlv.NewContextTag(0), noc)
		_ = enc.PutOctet(tlv.NewContextTag(2), ipk)
		_ = enc.PutUnsigned(tlv.NewContextTag(3), subject)
		enc.PutUnsigned2(tlv.NewContextTag(4), testAdminVendorID)
	})}
}

func rootRequest(t *testing.T, root []byte) *im.CommandRequest {
	t.Helper()
	return &im.CommandRequest{Fields: commandFields(t, func(enc tlv.Encoder) {
		_ = enc.PutOctet(tlv.NewContextTag(0), root)
	})}
}

func nocStatus(t *testing.T, result im.CommandResult) NOCStatus {
	t.Helper()
	if !result.HasResponse || result.ResponseCommand != nocResponseCommandID {
		t.Fatalf("answered with status %#x instead of a NOCResponse", result.Status)
	}
	dec := tlv.NewDecoderWithBytes(result.Fields)
	dec.Next()
	dec.Next()
	v, _ := dec.Element().Unsigned()
	return NOCStatus(v)
}

// stageKey sets the operational key a CSRRequest would have generated,
// and returns its CSR.
func stageKey(t *testing.T, oc *operationalCredentials) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := credentials.NewSoftwareSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := credentials.CreateCSR(signer)
	if err != nil {
		t.Fatal(err)
	}
	oc.mutex.Lock()
	oc.armedLocked()
	oc.pendingKey = key
	oc.mutex.Unlock()
	return csr
}

func TestAddNOCChecks(t *testing.T) {
	fs, _, s := newTestFailSafe(t)
	oc := newOperationalCredentials(s, fs, testAttestationProvider(t), DefaultSupportedFabrics)
	ca := newTestCA(t, testFabricID)

	// Without a fail-safe.
	if r := oc.addNOC(newAddNOCRequest(t, []byte{1}, testAdminNodeID, testIPK)); r.HasResponse || r.Status != im.StatusFailsafeRequired {
		t.Fatalf("AddNOC without a fail-safe: %+v", r)
	}
	if r := oc.addTrustedRootCertificate(rootRequest(t, ca.rootTLV(t))); r.Status != im.StatusFailsafeRequired {
		t.Fatalf("AddTrustedRootCertificate without a fail-safe: %+v", r)
	}
	if code := fs.arm(0, time.Minute); code != CommissioningOK {
		t.Fatal(code)
	}

	// Before CSRRequest and AddTrustedRootCertificate.
	if got := nocStatus(t, oc.addNOC(newAddNOCRequest(t, []byte{1}, testAdminNodeID, testIPK))); got != NOCStatusMissingCsr {
		t.Fatalf("AddNOC before CSRRequest: %d, want MissingCsr", got)
	}
	csr := stageKey(t, oc)
	noc := ca.issue(t, csr, testCommissioneeNode)
	if got := nocStatus(t, oc.addNOC(newAddNOCRequest(t, noc, testAdminNodeID, testIPK))); got != NOCStatusInvalidNOC {
		t.Fatalf("AddNOC before AddTrustedRootCertificate: %d, want InvalidNOC", got)
	}

	// A root must be a root, and only one is staged.
	if r := oc.addTrustedRootCertificate(rootRequest(t, noc)); r.Status != im.StatusInvalidCommand {
		t.Fatalf("AddTrustedRootCertificate(NOC): %+v", r)
	}
	if r := oc.addTrustedRootCertificate(rootRequest(t, ca.rootTLV(t))); r.HasResponse || r.Status != im.StatusSuccess {
		t.Fatalf("AddTrustedRootCertificate: %+v", r)
	}
	if r := oc.addTrustedRootCertificate(rootRequest(t, ca.rootTLV(t))); r.Status != im.StatusConstraintError {
		t.Fatalf("second AddTrustedRootCertificate: %+v", r)
	}

	// The NOC must be for the staged key, chain to the staged root, and
	// name a valid admin; the IPK is 16 bytes.
	other := ca.issue(t, stageKeyCSR(t), testCommissioneeNode)
	if got := nocStatus(t, oc.addNOC(newAddNOCRequest(t, other, testAdminNodeID, testIPK))); got != NOCStatusInvalidPublicKey {
		t.Fatalf("AddNOC for another key: %d, want InvalidPublicKey", got)
	}
	foreign := newTestCA(t, testFabricID).issue(t, csr, testCommissioneeNode)
	if got := nocStatus(t, oc.addNOC(newAddNOCRequest(t, foreign, testAdminNodeID, testIPK))); got != NOCStatusInvalidNOC {
		t.Fatalf("AddNOC under another root: %d, want InvalidNOC", got)
	}
	if got := nocStatus(t, oc.addNOC(newAddNOCRequest(t, noc, 0, testIPK))); got != NOCStatusInvalidAdminSubject {
		t.Fatalf("AddNOC with admin 0: %d, want InvalidAdminSubject", got)
	}
	if r := oc.addNOC(newAddNOCRequest(t, noc, testAdminNodeID, testIPK[:8])); r.Status != im.StatusInvalidCommand {
		t.Fatalf("AddNOC with a short IPK: %+v", r)
	}
	if got := nocStatus(t, oc.addNOC(newAddNOCRequest(t, noc, testAdminNodeID, testIPK))); got != NOCStatusOK {
		t.Fatalf("AddNOC: %d, want OK", got)
	}
	if code, err := fs.commit(1); code != CommissioningOK || err != nil {
		t.Fatalf("commit: (%d, %v)", code, err)
	}

	// Joining the same fabric again conflicts with the committed one.
	if code := fs.arm(0, time.Minute); code != CommissioningOK {
		t.Fatal(code)
	}
	csr = stageKey(t, oc)
	if r := oc.addTrustedRootCertificate(rootRequest(t, ca.rootTLV(t))); r.Status != im.StatusSuccess {
		t.Fatalf("AddTrustedRootCertificate under a new fail-safe: %+v", r)
	}
	again := ca.issue(t, csr, testCommissioneeNode+1)
	if got := nocStatus(t, oc.addNOC(newAddNOCRequest(t, again, testAdminNodeID, testIPK))); got != NOCStatusFabricConflict {
		t.Fatalf("AddNOC for a joined fabric: %d, want FabricConflict", got)
	}
}

// stageKeyCSR returns a CSR for a key the device did not generate.
func stageKeyCSR(t *testing.T) []byte {
	t.Helper()
	signer, err := credentials.GenerateSoftwareSigner()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := credentials.CreateCSR(signer)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

func TestAddNOCTableFull(t *testing.T) {
	fs, _, s := newTestFailSafe(t)
	for index := store.MinFabricIndex; index < store.MinFabricIndex+DefaultSupportedFabrics; index++ {
		if err := s.SaveDeviceFabric(store.DeviceFabricRecord{FabricIndex: index, FabricID: uint64(index), NodeID: 1}); err != nil {
			t.Fatal(err)
		}
	}
	oc := newOperationalCredentials(s, fs, testAttestationProvider(t), DefaultSupportedFabrics)
	ca := newTestCA(t, testFabricID)
	if code := fs.arm(0, time.Minute); code != CommissioningOK {
		t.Fatal(code)
	}
	noc := ca.issue(t, stageKey(t, oc), testCommissioneeNode)
	if r := oc.addTrustedRootCertificate(rootRequest(t, ca.rootTLV(t))); r.Status != im.StatusSuccess {
		t.Fatalf("AddTrustedRootCertificate: %+v", r)
	}
	if got := nocStatus(t, oc.addNOC(newAddNOCRequest(t, noc, testAdminNodeID, testIPK))); got != NOCStatusTableFull {
		t.Fatalf("AddNOC with every fabric used: %d, want TableFull", got)
	}
}

func TestFreeFabricIndex(t *testing.T) {
	recs := func(indexes ...uint8) []store.DeviceFabricRecord {
		out := make([]store.DeviceFabricRecord, 0, len(indexes))
		for _, i := range indexes {
			out = append(out, store.DeviceFabricRecord{FabricIndex: i})
		}
		return out
	}
	for _, tc := range []struct {
		fabrics []store.DeviceFabricRecord
		want    uint8
	}{
		{nil, 1},
		{recs(1, 2), 3},
		{recs(1, 3), 2},
		{recs(2), 1},
	} {
		if got, ok := freeFabricIndex(tc.fabrics); !ok || got != tc.want {
			t.Errorf("freeFabricIndex(%v) = (%d, %v), want %d", tc.fabrics, got, ok, tc.want)
		}
	}
}

// addNOCOverPASE takes a PASE session through ArmFailSafe, CSRRequest,
// AddTrustedRootCertificate and AddNOC for node on ca's fabric.
func addNOCOverPASE(t *testing.T, sess session.SecureSession, ca *testCA, node uint64) {
	t.Helper()
	if err := generalcommissioning.ArmFailSafe(sess, 0, 60, 1); err != nil {
		t.Fatal(err)
	}
	nocsr, _, err := operationalcredentials.CSRRequest(sess, 0, randomNonce(t))
	if err != nil {
		t.Fatal(err)
	}
	elements, err := credentials.ParseNOCSRElements(nocsr)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := credentials.ParseCSR(elements.CSR)
	if err != nil {
		t.Fatal(err)
	}
	nocDER, err := ca.ca.IssueNOC(csr, node)
	if err != nil {
		t.Fatal(err)
	}
	if err := operationalcredentials.AddTrustedRootCertificate(sess, 0, ca.rootDER); err != nil {
		t.Fatal(err)
	}
	if err := operationalcredentials.AddNOC(sess, 0, nocDER, nil, testIPK, testAdminNodeID, testAdminVendorID); err != nil {
		t.Fatal(err)
	}
}

// caseSession establishes CASE with the device as admin, over client.
func caseSession(t *testing.T, client *udpClient, admin config.AdministratorConfig, node uint64) session.SecureSession {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	keys, err := caseprotocol.NewInitiator(client, admin, caseprotocol.WithPeerNodeID(node), caseprotocol.WithIPK(testIPK)).EstablishSession(ctx)
	if err != nil {
		t.Fatalf("CASE: %v", err)
	}
	return session.NewSecureSession(client, keys)
}

// TestDeviceCommissioningCompletesOverCASE commissions the device to the
// end: after AddNOC over PASE, the commissioner establishes CASE with the
// new fabric's credentials and sends CommissioningComplete over it, which
// commits the fabric to the store.
func TestDeviceCommissioningCompletesOverCASE(t *testing.T) {
	d, pase, client := startCommissioningWithClient(t)
	ca := newTestCA(t, testFabricID)
	addNOCOverPASE(t, pase, ca, testCommissioneeNode)

	// The PASE session is now bound to the new fabric, so the
	// commissioner can keep extending the fail-safe over it.
	if err := generalcommissioning.ArmFailSafe(pase, 0, 60, 2); err != nil {
		t.Fatalf("ArmFailSafe over PASE after AddNOC: %v", err)
	}

	// A CASE session on another fabric is refused.
	other := newTestCA(t, testFabricID)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := caseprotocol.NewInitiator(client, other.admin(t, testAdminNodeID), caseprotocol.WithPeerNodeID(testCommissioneeNode), caseprotocol.WithIPK(testIPK)).EstablishSession(ctx); err == nil {
		t.Fatal("CASE succeeded under a root the device does not trust")
	}

	operational := caseSession(t, client, ca.admin(t, testAdminNodeID), testCommissioneeNode)
	if err := generalcommissioning.CommissioningComplete(operational, 0); err != nil {
		t.Fatalf("CommissioningComplete over CASE: %v", err)
	}
	if d.failSafe.isArmed() {
		t.Fatal("the fail-safe is still armed after CommissioningComplete")
	}
	fabrics, err := d.store.ListDeviceFabrics()
	if err != nil || len(fabrics) != 1 {
		t.Fatalf("the store holds (%d fabrics, %v) after CommissioningComplete, want 1", len(fabrics), err)
	}
	if f := fabrics[0]; f.FabricID != testFabricID || f.NodeID != testCommissioneeNode || f.FabricIndex != 1 {
		t.Fatalf("committed fabric %+v, want fabric 0x%X node 0x%X at index 1", f, testFabricID, testCommissioneeNode)
	}
	if acl, err := d.store.LoadACL(1); err != nil || len(acl) != 1 {
		t.Fatalf("committed ACL (%+v, %v), want the admin entry", acl, err)
	}

	// The operational session keeps serving the Interaction Model, and a
	// new CASE session can be established on the committed fabric.
	if n := readUint8(t, operational, commissionedFabricsAttributeID); n != 1 {
		t.Fatalf("CommissionedFabrics over CASE = %d, want 1", n)
	}
	again := caseSession(t, client, ca.admin(t, testAdminNodeID+1), testCommissioneeNode)
	if n := readUint8(t, again, commissionedFabricsAttributeID); n != 1 {
		t.Fatalf("CommissionedFabrics over a second CASE session = %d, want 1", n)
	}
}

// TestDeviceRollbackClosesCASESessions checks that the CASE sessions on a
// fabric the fail-safe rolls back end with it.
func TestDeviceRollbackClosesCASESessions(t *testing.T) {
	d, pase, client := startCommissioningWithClient(t)
	ca := newTestCA(t, testFabricID)
	addNOCOverPASE(t, pase, ca, testCommissioneeNode)
	caseSession(t, client, ca.admin(t, testAdminNodeID), testCommissioneeNode)

	countCASE := func() int {
		d.mu.Lock()
		defer d.mu.Unlock()
		n := 0
		for _, s := range d.sessions {
			if s.isCASE {
				n++
			}
		}
		return n
	}
	if n := countCASE(); n != 1 {
		t.Fatalf("%d CASE sessions after CASE, want 1", n)
	}
	if err := generalcommissioning.ArmFailSafe(pase, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	if n := countCASE(); n != 0 {
		t.Fatalf("%d CASE sessions after the fail-safe rolled back, want 0", n)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, s := range d.sessions {
		if !s.isCASE && s.fabricIndex != 0 {
			t.Fatalf("the PASE session is still bound to fabric %d", s.fabricIndex)
		}
	}
}
