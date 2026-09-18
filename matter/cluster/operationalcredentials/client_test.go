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

package operationalcredentials

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/cybergarage/go-matter/matter/credentials/chipcert"
	"github.com/cybergarage/go-matter/matter/encoding/message"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	"github.com/cybergarage/go-matter/matter/protocol/session"
)

// fakeSession is a minimal session.SecureSession that records the last
// transmitted (unencrypted, per the SecureSession.Transmit contract) wire
// bytes and returns a preconfigured response to the next Receive call.
type fakeSession struct {
	lastTransmit []byte
	nextReceive  []byte
	receiveErr   error
}

func (s *fakeSession) Transmit(payload []byte) error {
	s.lastTransmit = append([]byte(nil), payload...)
	return nil
}

// Receive echoes s.nextReceive back with its ExchangeID (protocol header
// bytes 2:4, a fixed offset regardless of other header flags) patched to
// match whatever ExchangeID the code under test actually transmitted —
// im.Invoke now rejects any response whose ExchangeID doesn't match its
// request's freshly-generated random one (see im.receiveExchangeResponse),
// so a canned response built with an unrelated ExchangeID would otherwise
// never match and Receive would be called forever.
func (s *fakeSession) Receive() ([]byte, error) {
	if s.receiveErr != nil {
		return nil, s.receiveErr
	}
	resp := append([]byte(nil), s.nextReceive...)
	if len(resp) >= 4 && len(s.lastTransmit) >= 4 {
		copy(resp[2:4], s.lastTransmit[2:4])
	}
	return resp, nil
}
func (s *fakeSession) Transport() session.Transport     { return nil }
func (s *fakeSession) SessionKeys() session.SessionKeys { return nil }

// decodeTransmittedCommandFields strips the IM protocol header from a
// transmitted InvokeRequest and decodes the invoke-requests[0].command-fields
// structure into a flat context-tag -> element map, for assertions.
func decodeTransmittedCommandFields(t *testing.T, wire []byte) map[uint8]tlv.Element {
	t.Helper()
	hdr, err := message.NewProtocolHeaderFromBytes(wire)
	if err != nil {
		t.Fatalf("parse protocol header: %v", err)
	}
	hdrBytes, err := hdr.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	dec := tlv.NewDecoderWithBytes(wire[len(hdrBytes):])

	out := make(map[uint8]tlv.Element)
	depth := 0
	var commandFieldsDepth = -1
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			depth--
			if depth == commandFieldsDepth {
				commandFieldsDepth = -1
			}
			continue
		}
		if commandFieldsDepth == -1 {
			// Looking for context tag 1 (command-fields) inside
			// command-data-IB. Depth counts enclosing containers already
			// entered: top structure=1, invoke-requests list=2,
			// command-data-IB=3 — command-fields is a child of the latter.
			if ct, ok := elem.Tag().(tlv.ContextTag); ok && ct.ContextNumber() == 1 && depth == 3 && elem.Type().IsStructure() {
				commandFieldsDepth = depth
				depth++
				continue
			}
		} else if depth == commandFieldsDepth+1 {
			if ct, ok := elem.Tag().(tlv.ContextTag); ok {
				out[uint8(ct.ContextNumber())] = elem
			}
		}
		if elem.Type().IsStructure() || elem.Type().IsList() || elem.Type().IsArray() {
			depth++
		}
	}
	return out
}

func buildSuccessInvokeResponse(t *testing.T, buildFields func(enc tlv.Encoder)) []byte {
	t.Helper()
	hdr := message.NewProtocolHeader(
		message.WithHeaderExchangeFlags(message.ReliabilityFlag),
		message.WithHeaderOpcode(message.InvokeResponseMessage),
		message.WithHeaderExchangeID(message.NewFirstExchangeID()),
		message.WithHeaderProtocolID(message.InteractionModel),
	)
	hdrBytes, err := hdr.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	enc.PutBool(tlv.NewContextTag(0), false)
	enc.BeginList(tlv.NewContextTag(1))
	enc.BeginStructure(tlv.NewAnonymousTag()) // InvokeResponseIB
	enc.BeginStructure(tlv.NewContextTag(0))  // CommandDataIB
	enc.BeginStructure(tlv.NewContextTag(0))  // CommandPathIB
	enc.PutUnsigned2(tlv.NewContextTag(0), 0)
	if err := enc.PutUnsigned(tlv.NewContextTag(1), uint64(ClusterID)); err != nil {
		t.Fatal(err)
	}
	if err := enc.PutUnsigned(tlv.NewContextTag(2), 0); err != nil {
		t.Fatal(err)
	}
	if err := enc.EndContainer(); err != nil { // end CommandPathIB
		t.Fatal(err)
	}
	enc.BeginStructure(tlv.NewContextTag(1)) // CommandFields
	if buildFields != nil {
		buildFields(enc)
	}
	if err := enc.EndContainer(); err != nil { // end CommandFields
		t.Fatal(err)
	}
	if err := enc.EndContainer(); err != nil { // end CommandDataIB
		t.Fatal(err)
	}
	if err := enc.EndContainer(); err != nil { // end InvokeResponseIB
		t.Fatal(err)
	}
	if err := enc.EndContainer(); err != nil { // end invoke-responses
		t.Fatal(err)
	}
	if err := enc.EndContainer(); err != nil { // end top-level
		t.Fatal(err)
	}

	return append(hdrBytes, enc.Bytes()...)
}

func TestAttestationRequestEncodesNonceAndDecodesResponse(t *testing.T) {
	nonce := bytes.Repeat([]byte{0x01}, 32)
	elements := []byte{0xAA, 0xBB}
	sig := bytes.Repeat([]byte{0x02}, 64)

	sess := &fakeSession{
		nextReceive: buildSuccessInvokeResponse(t, func(enc tlv.Encoder) {
			if err := enc.PutOctet(tlv.NewContextTag(0), elements); err != nil {
				t.Fatal(err)
			}
			if err := enc.PutOctet(tlv.NewContextTag(1), sig); err != nil {
				t.Fatal(err)
			}
		}),
	}

	gotElements, gotSig, err := AttestationRequest(sess, 0, nonce)
	if err != nil {
		t.Fatalf("AttestationRequest() error = %v", err)
	}
	if !bytes.Equal(gotElements, elements) {
		t.Errorf("AttestationElements = %v, want %v", gotElements, elements)
	}
	if !bytes.Equal(gotSig, sig) {
		t.Errorf("Signature = %v, want %v", gotSig, sig)
	}

	fields := decodeTransmittedCommandFields(t, sess.lastTransmit)
	elem, ok := fields[0]
	if !ok {
		t.Fatal("transmitted request missing field 0 (AttestationNonce)")
	}
	got, ok := elem.Bytes()
	if !ok || !bytes.Equal(got, nonce) {
		t.Errorf("transmitted AttestationNonce = %v, %v; want %v, true", got, ok, nonce)
	}
}

// TestCertificateChainRequestDecodesCertificate guards against a regression
// where CertificateChainRequest ran chipcert.TLVToDER on the response's
// Certificate field. A real device's CertificateChainResponse carries the
// DAC/PAI as plain DER already (unlike the fabric's own NOC/ICAC/RCAC, which
// do use the compact Matter-TLV CHIPCert encoding for AddNOC/
// AddTrustedRootCertificate) — running TLVToDER on it failed immediately
// with "expected top-level Structure" since a DER certificate's first byte
// (0x30, SEQUENCE) is never a valid Matter-TLV control byte.
func TestCertificateChainRequestDecodesCertificate(t *testing.T) {
	certDER := generateSelfSignedCert(t)

	sess := &fakeSession{
		nextReceive: buildSuccessInvokeResponse(t, func(enc tlv.Encoder) {
			if err := enc.PutOctet(tlv.NewContextTag(0), certDER); err != nil {
				t.Fatal(err)
			}
		}),
	}

	got, err := CertificateChainRequest(sess, 0, 1)
	if err != nil {
		t.Fatalf("CertificateChainRequest() error = %v", err)
	}
	if !bytes.Equal(got, certDER) {
		t.Error("CertificateChainRequest() did not return the expected DER certificate")
	}

	fields := decodeTransmittedCommandFields(t, sess.lastTransmit)
	elem, ok := fields[0]
	if !ok {
		t.Fatal("transmitted request missing field 0 (CertificateType)")
	}
	v, ok := elem.Unsigned1()
	if !ok || v != 1 {
		t.Errorf("transmitted CertificateType = %v, %v; want 1, true", v, ok)
	}
}

func TestAddNOCEncodesAllFields(t *testing.T) {
	nocDER := generateSelfSignedCert(t)
	ipk := bytes.Repeat([]byte{0x03}, 16)

	sess := &fakeSession{
		nextReceive: buildSuccessInvokeResponse(t, func(enc tlv.Encoder) {
			enc.PutUnsigned1(tlv.NewContextTag(0), nocStatusOK)
		}),
	}

	if err := AddNOC(sess, 0, nocDER, nil, ipk, 0xAB, 0xCD); err != nil {
		t.Fatalf("AddNOC() error = %v", err)
	}

	fields := decodeTransmittedCommandFields(t, sess.lastTransmit)
	nocElem, ok := fields[0]
	if !ok {
		t.Fatal("transmitted request missing field 0 (NOCValue)")
	}
	nocTLV, ok := nocElem.Bytes()
	if !ok {
		t.Fatal("NOCValue is not an octet string")
	}
	gotDER, err := chipcert.TLVToDER(nocTLV)
	if err != nil {
		t.Fatalf("decode transmitted NOCValue: %v", err)
	}
	if !bytes.Equal(gotDER, nocDER) {
		t.Error("transmitted NOCValue does not decode back to the original NOC DER")
	}
	if _, ok := fields[1]; ok {
		t.Error("transmitted request unexpectedly includes field 1 (ICACValue) when none was given")
	}
	ipkElem, ok := fields[2]
	if !ok {
		t.Fatal("transmitted request missing field 2 (IPKValue)")
	}
	gotIPK, ok := ipkElem.Bytes()
	if !ok || !bytes.Equal(gotIPK, ipk) {
		t.Errorf("transmitted IPKValue = %v, %v; want %v, true", gotIPK, ok, ipk)
	}
	subjElem, ok := fields[3]
	if !ok {
		t.Fatal("transmitted request missing field 3 (CaseAdminSubject)")
	}
	if v, ok := subjElem.Unsigned(); !ok || v != 0xAB {
		t.Errorf("transmitted CaseAdminSubject = %v, %v; want 0xAB, true", v, ok)
	}
	vidElem, ok := fields[4]
	if !ok {
		t.Fatal("transmitted request missing field 4 (AdminVendorId)")
	}
	if v, ok := vidElem.Unsigned2(); !ok || v != 0xCD {
		t.Errorf("transmitted AdminVendorId = %v, %v; want 0xCD, true", v, ok)
	}
}

func TestAddNOCFailsOnNonSuccessStatus(t *testing.T) {
	nocDER := generateSelfSignedCert(t)
	sess := &fakeSession{
		nextReceive: buildSuccessInvokeResponse(t, func(enc tlv.Encoder) {
			enc.PutUnsigned1(tlv.NewContextTag(0), 2) // arbitrary non-zero NOCStatus
		}),
	}
	if err := AddNOC(sess, 0, nocDER, nil, []byte("ipk"), 1, 1); err == nil {
		t.Fatal("AddNOC() error = nil, want non-nil for non-success NOCResponse status")
	}
}

func generateSelfSignedCert(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
