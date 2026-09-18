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

package networkcommissioning

import (
	"bytes"
	"testing"

	"github.com/cybergarage/go-matter/matter/encoding/message"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	"github.com/cybergarage/go-matter/matter/protocol/session"
)

type fakeSession struct {
	lastTransmit []byte
	nextReceive  []byte
}

func (s *fakeSession) Transmit(payload []byte) error {
	s.lastTransmit = append([]byte(nil), payload...)
	return nil
}
func (s *fakeSession) Receive() ([]byte, error)         { return s.nextReceive, nil }
func (s *fakeSession) Transport() session.Transport     { return nil }
func (s *fakeSession) SessionKeys() session.SessionKeys { return nil }

// decodeTransmittedCommandFields decodes the command-fields structure (the
// Context(1) Structure nested inside command-data-IB, itself nested inside
// invoke-requests[0]) of a transmitted InvokeRequest into a flat map.
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
	commandFieldsDepth := -1
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

func TestAddOrUpdateWiFiNetworkEncodesFieldsAndSucceeds(t *testing.T) {
	ssid := []byte("my-network")
	creds := []byte("hunter2")

	sess := &fakeSession{
		nextReceive: buildSuccessInvokeResponse(t, func(enc tlv.Encoder) {
			enc.PutUnsigned1(tlv.NewContextTag(0), NetworkingStatusSuccess)
		}),
	}

	if err := AddOrUpdateWiFiNetwork(sess, 0, ssid, creds, 7); err != nil {
		t.Fatalf("AddOrUpdateWiFiNetwork() error = %v", err)
	}

	fields := decodeTransmittedCommandFields(t, sess.lastTransmit)
	ssidElem, ok := fields[0]
	if !ok {
		t.Fatal("transmitted request missing field 0 (SSID)")
	}
	if got, ok := ssidElem.Bytes(); !ok || !bytes.Equal(got, ssid) {
		t.Errorf("transmitted SSID = %v, %v; want %v, true", got, ok, ssid)
	}
	credsElem, ok := fields[1]
	if !ok {
		t.Fatal("transmitted request missing field 1 (Credentials)")
	}
	if got, ok := credsElem.Bytes(); !ok || !bytes.Equal(got, creds) {
		t.Errorf("transmitted Credentials = %v, %v; want %v, true", got, ok, creds)
	}
	breadcrumbElem, ok := fields[2]
	if !ok {
		t.Fatal("transmitted request missing field 2 (Breadcrumb)")
	}
	if got, ok := breadcrumbElem.Unsigned(); !ok || got != 7 {
		t.Errorf("transmitted Breadcrumb = %v, %v; want 7, true", got, ok)
	}
}

func TestAddOrUpdateWiFiNetworkFailsOnNonSuccessStatus(t *testing.T) {
	sess := &fakeSession{
		nextReceive: buildSuccessInvokeResponse(t, func(enc tlv.Encoder) {
			enc.PutUnsigned1(tlv.NewContextTag(0), 1) // arbitrary non-zero NetworkingStatus
		}),
	}
	if err := AddOrUpdateWiFiNetwork(sess, 0, []byte("ssid"), []byte("pw"), 0); err == nil {
		t.Fatal("AddOrUpdateWiFiNetwork() error = nil, want non-nil for non-success status")
	}
}

func TestConnectNetworkEncodesFieldsAndSucceeds(t *testing.T) {
	networkID := []byte("my-network")

	sess := &fakeSession{
		nextReceive: buildSuccessInvokeResponse(t, func(enc tlv.Encoder) {
			enc.PutUnsigned1(tlv.NewContextTag(0), NetworkingStatusSuccess)
		}),
	}

	if err := ConnectNetwork(sess, 0, networkID, 3); err != nil {
		t.Fatalf("ConnectNetwork() error = %v", err)
	}

	fields := decodeTransmittedCommandFields(t, sess.lastTransmit)
	idElem, ok := fields[0]
	if !ok {
		t.Fatal("transmitted request missing field 0 (NetworkID)")
	}
	if got, ok := idElem.Bytes(); !ok || !bytes.Equal(got, networkID) {
		t.Errorf("transmitted NetworkID = %v, %v; want %v, true", got, ok, networkID)
	}
}
