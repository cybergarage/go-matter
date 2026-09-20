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

package im

import (
	"testing"

	"github.com/cybergarage/go-matter/matter/encoding/message"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
)

// TestBuildWriteRequestPayloadContainerTypes guards against the same class
// of container-type regression already fixed for InvokeRequestMessage (see
// TestBuildInvokeRequestPayloadContainerTypes): write-requests (ContextTag
// 2) must be an Array and attribute-path-IB (nested AttributeDataIB tag 1)
// must be a List, matching connectedhomeip's WriteRequests
// (ArrayParser/ArrayBuilder) and AttributePathIB
// (ListParser/ListBuilder) definitions.
func TestBuildWriteRequestPayloadContainerTypes(t *testing.T) {
	payload, err := buildWriteRequestPayload(0, 0x0006, 0x0000, func(enc tlv.Encoder) error {
		enc.PutBool(tlv.NewContextTag(2), true)
		return nil
	})
	if err != nil {
		t.Fatalf("buildWriteRequestPayload() error = %v", err)
	}

	dec := tlv.NewDecoderWithBytes(payload)
	if !dec.Next() || !dec.Element().Type().IsStructure() {
		t.Fatal("expected top-level Structure")
	}
	if !dec.Next() || !dec.Element().Type().IsBool() { // suppress-response
		t.Fatal("expected suppress-response Bool")
	}
	if !dec.Next() || !dec.Element().Type().IsBool() { // timed-request
		t.Fatal("expected timed-request Bool")
	}
	if !dec.Next() || !dec.Element().Type().IsArray() {
		t.Fatalf("write-requests must be an Array, got %v", dec.Element().Type())
	}
	if !dec.Next() || !dec.Element().Type().IsStructure() { // attribute-data-IB
		t.Fatal("expected attribute-data-IB Structure")
	}
	if !dec.Next() || !dec.Element().Type().IsList() {
		t.Fatalf("attribute-path-IB must be a List, got %v", dec.Element().Type())
	}
}

// TestBuildWriteRequestPayloadEncodesData verifies encodeData's output lands
// at the AttributeDataIB's Data field (tag 2) and that the AttributePathIB
// fields are encoded correctly.
func TestBuildWriteRequestPayloadEncodesData(t *testing.T) {
	payload, err := buildWriteRequestPayload(1, 0x0006, 0x0000, func(enc tlv.Encoder) error {
		enc.PutBool(tlv.NewContextTag(2), true)
		return nil
	})
	if err != nil {
		t.Fatalf("buildWriteRequestPayload() error = %v", err)
	}

	dec := tlv.NewDecoderWithBytes(payload)
	if !dec.Next() || !dec.Element().Type().IsStructure() {
		t.Fatal("expected top-level Structure")
	}
	if !dec.Next() { // suppress-response
		t.Fatal("expected suppress-response")
	}
	if !dec.Next() { // timed-request
		t.Fatal("expected timed-request")
	}
	if !dec.Next() || !dec.Element().Type().IsArray() { // write-requests
		t.Fatal("expected write-requests Array")
	}
	if !dec.Next() || !dec.Element().Type().IsStructure() { // attribute-data-IB
		t.Fatal("expected attribute-data-IB Structure")
	}
	if !dec.Next() || !dec.Element().Type().IsList() { // attribute-path-IB
		t.Fatal("expected attribute-path-IB List")
	}
	seen := map[uint8]tlv.Element{}
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			break
		}
		ct, ok := elem.Tag().(tlv.ContextTag)
		if !ok {
			t.Fatalf("unexpected non-context tag element: %+v", elem)
		}
		seen[uint8(ct.ContextNumber())] = elem
	}
	endpoint, ok := seen[2]
	if !ok {
		t.Fatal("AttributePathIB missing Endpoint (tag 2)")
	}
	if v, ok := endpoint.Unsigned2(); !ok || v != 1 {
		t.Errorf("Endpoint = %v, %v; want 1, true", v, ok)
	}
	cluster, ok := seen[3]
	if !ok {
		t.Fatal("AttributePathIB missing Cluster (tag 3)")
	}
	if v, ok := cluster.Unsigned4(); !ok || v != 0x0006 {
		t.Errorf("Cluster = %#x, %v; want 0x6, true", v, ok)
	}

	// Next element after AttributePathIB's EndOfContainer is the Data field
	// (tag 2 of attribute-data-IB), i.e. encodeData's output.
	if !dec.Next() {
		t.Fatal("expected Data element after AttributePathIB")
	}
	dataElem := dec.Element()
	dct, ok := dataElem.Tag().(tlv.ContextTag)
	if !ok || dct.ContextNumber() != 2 {
		t.Fatalf("Data element tag = %+v, want ContextTag(2)", dataElem.Tag())
	}
	if v, ok := dataElem.Bool(); !ok || !v {
		t.Errorf("Data = %v, %v; want true, true", v, ok)
	}
}

// TestBuildWriteRequestPayloadEncodesInteractionModelRevision mirrors
// buildReadRequestPayload/buildInvokeRequestPayload's own regression test —
// the mandatory trailing field (spec 8.2.1) on every IM request message.
func TestBuildWriteRequestPayloadEncodesInteractionModelRevision(t *testing.T) {
	payload, err := buildWriteRequestPayload(0, 0x0006, 0x0000, func(enc tlv.Encoder) error {
		enc.PutBool(tlv.NewContextTag(2), false)
		return nil
	})
	if err != nil {
		t.Fatalf("buildWriteRequestPayload() error = %v", err)
	}

	fields, err := topLevelFields(payload)
	if err != nil {
		t.Fatalf("topLevelFields() error = %v", err)
	}
	elem, ok := fields[0xFF]
	if !ok {
		t.Fatal("WriteRequestMessage missing mandatory InteractionModelRevision field (tag 0xFF)")
	}
	v, ok := elem.Unsigned1()
	if !ok || v != 12 {
		t.Errorf("InteractionModelRevision = %v, %v; want 12, true", v, ok)
	}
}

// TestBuildWriteRequestPayloadRequiresEncodeData guards against a nil
// encodeData silently producing an AttributeDataIB with no Data field.
func TestBuildWriteRequestPayloadRequiresEncodeData(t *testing.T) {
	if _, err := buildWriteRequestPayload(0, 0x0006, 0x0000, nil); err == nil {
		t.Fatal("buildWriteRequestPayload(..., nil) error = nil, want non-nil")
	}
}

func buildWriteResponseMessage(t *testing.T, buildStatuses func(enc tlv.Encoder)) []byte {
	t.Helper()
	hdr := message.NewProtocolHeader(
		message.WithHeaderExchangeFlags(message.ReliabilityFlag),
		message.WithHeaderOpcode(message.WriteResponseMessage),
		message.WithHeaderExchangeID(message.NewFirstExchangeID()),
		message.WithHeaderProtocolID(message.InteractionModel),
	)
	hdrBytes, err := hdr.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	enc.BeginArray(tlv.NewContextTag(0)) // write-responses
	buildStatuses(enc)
	if err := enc.EndContainer(); err != nil { // end write-responses
		t.Fatal(err)
	}
	enc.PutUnsigned1(tlv.NewContextTag(interactionModelRevisionTag), interactionModelRevision)
	if err := enc.EndContainer(); err != nil {
		t.Fatal(err)
	}

	return append(hdrBytes, enc.Bytes()...)
}

func TestParseWriteResponseStatusSuccess(t *testing.T) {
	data := buildWriteResponseMessage(t, func(enc tlv.Encoder) {
		enc.BeginStructure(tlv.NewAnonymousTag()) // AttributeStatusIB
		enc.BeginList(tlv.NewContextTag(0))       // AttributePathIB
		enc.PutUnsigned2(tlv.NewContextTag(2), 0)
		if err := enc.EndContainer(); err != nil {
			t.Fatal(err)
		}
		enc.BeginStructure(tlv.NewContextTag(1))  // StatusIB
		enc.PutUnsigned1(tlv.NewContextTag(0), 0) // Success
		if err := enc.EndContainer(); err != nil {
			t.Fatal(err)
		}
		if err := enc.EndContainer(); err != nil { // end AttributeStatusIB
			t.Fatal(err)
		}
	})

	resp, err := parseWriteResponse(data)
	if err != nil {
		t.Fatalf("parseWriteResponse() error = %v", err)
	}
	if !resp.IsSuccess() {
		t.Errorf("IsSuccess() = false, want true (Status=%+v)", resp.Status)
	}
}

func TestParseWriteResponseStatusFailure(t *testing.T) {
	data := buildWriteResponseMessage(t, func(enc tlv.Encoder) {
		enc.BeginStructure(tlv.NewAnonymousTag()) // AttributeStatusIB
		enc.BeginList(tlv.NewContextTag(0))       // AttributePathIB
		enc.PutUnsigned2(tlv.NewContextTag(2), 0)
		if err := enc.EndContainer(); err != nil {
			t.Fatal(err)
		}
		enc.BeginStructure(tlv.NewContextTag(1))     // StatusIB
		enc.PutUnsigned1(tlv.NewContextTag(0), 0x87) // UnsupportedWrite
		if err := enc.EndContainer(); err != nil {
			t.Fatal(err)
		}
		if err := enc.EndContainer(); err != nil { // end AttributeStatusIB
			t.Fatal(err)
		}
	})

	resp, err := parseWriteResponse(data)
	if err != nil {
		t.Fatalf("parseWriteResponse() error = %v", err)
	}
	if resp.IsSuccess() {
		t.Fatal("IsSuccess() = true, want false")
	}
	if resp.Status.IMStatus != 0x87 {
		t.Errorf("Status.IMStatus = %#x, want 0x87", resp.Status.IMStatus)
	}
}

// TestParseWriteResponseHandlesStatusResponseMessage guards against the same
// failure mode already covered for Read/Invoke: a device rejecting the
// whole WriteRequestMessage replies with a StatusResponseMessage instead of
// a WriteResponseMessage.
func TestParseWriteResponseHandlesStatusResponseMessage(t *testing.T) {
	hdr := message.NewProtocolHeader(
		message.WithHeaderExchangeFlags(message.ReliabilityFlag),
		message.WithHeaderOpcode(message.StatusResponseMessage),
		message.WithHeaderExchangeID(message.NewFirstExchangeID()),
		message.WithHeaderProtocolID(message.InteractionModel),
	)
	hdrBytes, err := hdr.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	enc.PutUnsigned1(tlv.NewContextTag(0), 0x80) // Status: InvalidAction
	enc.PutUnsigned1(tlv.NewContextTag(0xFF), 1) // InteractionModelRevision
	if err := enc.EndContainer(); err != nil {
		t.Fatal(err)
	}
	data := append(append([]byte{}, hdrBytes...), enc.Bytes()...)

	resp, err := parseWriteResponse(data)
	if err != nil {
		t.Fatalf("parseWriteResponse() error = %v", err)
	}
	if resp.IsSuccess() {
		t.Fatal("IsSuccess() = true, want false for a StatusResponseMessage")
	}
	if resp.Status.IMStatus != 0x80 {
		t.Errorf("Status.IMStatus = %#x, want 0x80", resp.Status.IMStatus)
	}
}
