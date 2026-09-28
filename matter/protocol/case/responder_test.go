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

package caseprotocol

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
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/cybergarage/go-matter/matter/config"
	"github.com/cybergarage/go-matter/matter/credentials"
	"github.com/cybergarage/go-matter/matter/credentials/chipcert"
	"github.com/cybergarage/go-matter/matter/encoding/message"
	"github.com/cybergarage/go-matter/matter/protocol/session"
)

// pipeTransport is one end of an in-memory datagram pipe.
type pipeTransport struct {
	in  chan []byte
	out chan []byte
}

func newPipe() (*pipeTransport, *pipeTransport) {
	a, b := make(chan []byte, 16), make(chan []byte, 16)
	return &pipeTransport{in: a, out: b}, &pipeTransport{in: b, out: a}
}

func (p *pipeTransport) Transmit(ctx context.Context, b []byte) error {
	select {
	case p.out <- bytes.Clone(b):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *pipeTransport) Receive(ctx context.Context) ([]byte, error) {
	select {
	case b := <-p.in:
		return b, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// testFabric is a fabric with an administrator, which initiates CASE, and
// a device, which responds.
type testFabric struct {
	fabricID uint64
	admin    config.AdministratorConfig
	device   ResponderFabric
}

const (
	testFabricID    = 0x2906C908D115D362
	testAdminNode   = 0x0000000000000001
	testDeviceNode  = 0x00000000DEADBEEF
	testFabricIndex = 3
)

var testIPK = []byte("0123456789abcdef")

func newTestFabric(t *testing.T, fabricID uint64) testFabric {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootPub, err := rootKey.PublicKey.ECDH()
	if err != nil {
		t.Fatal(err)
	}
	skid := sha1.Sum(rootPub.Bytes())
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{ExtraNames: []pkix.AttributeTypeAndValue{{
			Type:  asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37244, 1, 4},
			Value: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagUTF8String, Bytes: []byte("0000000000000001")},
		}}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          skid[:],
		AuthorityKeyId:        skid[:],
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootKeyDER, err := x509.MarshalPKCS8PrivateKey(rootKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := credentials.NewCertificateAuthority(rootDER, rootKeyDER, fabricID)
	if err != nil {
		t.Fatal(err)
	}
	issue := func(nodeID uint64) ([]byte, *ecdsa.PrivateKey, credentials.Signer) {
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
		noc, err := ca.IssueNOC(csr, nodeID)
		if err != nil {
			t.Fatal(err)
		}
		return noc, key, signer
	}

	adminNOC, adminKey, _ := issue(testAdminNode)
	adminKeyDER, err := x509.MarshalPKCS8PrivateKey(adminKey)
	if err != nil {
		t.Fatal(err)
	}
	deviceNOC, _, deviceSigner := issue(testDeviceNode)
	tlvOf := func(der []byte) []byte {
		b, err := chipcert.DERToTLV(der)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	return testFabric{
		fabricID: fabricID,
		admin: config.NewAdministratorConfig(
			config.WithAdministratorNodeID(testAdminNode),
			config.WithAdministratorFabricID(fabricID),
			config.WithAdministratorRootCertificate(rootDER),
			config.WithAdministratorRootPrivateKey(rootKeyDER),
			config.WithAdministratorNOC(adminNOC),
			config.WithAdministratorPrivateKey(adminKeyDER),
		),
		device: ResponderFabric{
			FabricIndex:   testFabricIndex,
			FabricID:      fabricID,
			NodeID:        testDeviceNode,
			RootPublicKey: rootPub.Bytes(),
			RCAC:          tlvOf(rootDER),
			ICAC:          nil,
			NOC:           tlvOf(deviceNOC),
			IPK:           testIPK,
			Signer:        deviceSigner,
		},
	}
}

type responderResult struct {
	sess *ResponderSession
	err  error
}

// runCASE runs go-matter's CASE initiator against a Responder on fabrics.
func runCASE(t *testing.T, admin config.AdministratorConfig, peerNodeID uint64, fabrics []ResponderFabric) (responderResult, session.SessionKeys, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	initiatorEnd, responderEnd := newPipe()
	results := make(chan responderResult, 1)
	go func() {
		sess, err := NewResponder(responderEnd, func() ([]ResponderFabric, error) { return fabrics, nil }).EstablishSession(ctx)
		results <- responderResult{sess: sess, err: err}
	}()
	keys, err := NewInitiator(initiatorEnd, admin, WithPeerNodeID(peerNodeID), WithIPK(testIPK)).EstablishSession(ctx)
	return <-results, keys, err
}

func TestResponderEstablishesSessionWithInitiator(t *testing.T) {
	fabric := newTestFabric(t, testFabricID)
	other := newTestFabric(t, testFabricID+1)
	other.device.FabricIndex = testFabricIndex + 1

	res, keys, err := runCASE(t, fabric.admin, testDeviceNode, []ResponderFabric{other.device, fabric.device})
	if err != nil {
		t.Fatalf("Initiator.EstablishSession() error = %v", err)
	}
	if res.err != nil {
		t.Fatalf("Responder.EstablishSession() error = %v", res.err)
	}
	dev := res.sess
	if dev.FabricIndex != testFabricIndex || dev.PeerNodeID != testAdminNode {
		t.Fatalf("responder session on fabric %d with peer 0x%X, want fabric %d with 0x%X", dev.FabricIndex, dev.PeerNodeID, testFabricIndex, testAdminNode)
	}
	if !bytes.Equal(dev.Keys.I2RKey(), keys.I2RKey()) || !bytes.Equal(dev.Keys.R2IKey(), keys.R2IKey()) {
		t.Fatal("the initiator and the responder derived different session keys")
	}
	if dev.Keys.InitiatorSessionID() != keys.InitiatorSessionID() || dev.Keys.ResponderSessionID() != keys.ResponderSessionID() {
		t.Fatal("the initiator and the responder disagree on the session IDs")
	}
	if dev.Keys.LocalNodeID() != keys.PeerNodeID() || dev.Keys.PeerNodeID() != keys.LocalNodeID() {
		t.Fatal("the node IDs of the two sides do not mirror each other")
	}

	// The keys carry messages both ways.
	initiatorEnd, responderEnd := newPipe()
	initiator := session.NewSecureSession(initiatorEnd, keys)
	responder := session.NewSecureSession(responderEnd, dev.Keys, session.WithRole(session.RoleResponder))
	if err := initiator.Transmit(testProtocolPayload(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := responder.Receive(); err != nil {
		t.Fatalf("the responder cannot decrypt the initiator's message: %v", err)
	}
}

func TestResponderRejectsUnknownFabric(t *testing.T) {
	fabric := newTestFabric(t, testFabricID)
	other := newTestFabric(t, testFabricID)
	res, _, err := runCASE(t, fabric.admin, testDeviceNode, []ResponderFabric{other.device})
	if !errors.Is(res.err, ErrNoSharedTrustRoot) {
		t.Fatalf("Responder.EstablishSession() error = %v, want ErrNoSharedTrustRoot", res.err)
	}
	if err == nil {
		t.Fatal("the initiator established a session without a shared root")
	}
}

func TestResponderRejectsInitiatorOfAnotherRoot(t *testing.T) {
	fabric := newTestFabric(t, testFabricID)
	// The device is on the administrator's fabric by its destination ID,
	// but trusts another root.
	impostor := newTestFabric(t, testFabricID)
	device := fabric.device
	device.RCAC = impostor.device.RCAC
	res, _, err := runCASE(t, fabric.admin, testDeviceNode, []ResponderFabric{device})
	if !errors.Is(res.err, ErrInvalidInitiator) {
		t.Fatalf("Responder.EstablishSession() error = %v, want ErrInvalidInitiator", res.err)
	}
	if err == nil {
		t.Fatal("the initiator established a session the responder refused")
	}
}

// testProtocolPayload is an Interaction Model protocol header with no
// payload, to send over a secure session.
func testProtocolPayload(t *testing.T) []byte {
	t.Helper()
	b, err := message.NewProtocolHeader(
		message.WithHeaderExchangeFlags(message.InitiatorFlag),
		message.WithHeaderOpcode(message.StatusResponseMessage),
		message.WithHeaderExchangeID(1),
		message.WithHeaderProtocolID(message.InteractionModel),
	).Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return b
}
