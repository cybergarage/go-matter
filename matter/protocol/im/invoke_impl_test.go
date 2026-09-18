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

func buildInvokeResponseMessage(t *testing.T, buildFields func(enc tlv.Encoder)) []byte {
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
	enc.PutBool(tlv.NewContextTag(0), false) // suppress-response
	enc.BeginList(tlv.NewContextTag(1))      // invoke-responses
	buildFields(enc)
	if err := enc.EndContainer(); err != nil { // end invoke-responses
		t.Fatal(err)
	}
	if err := enc.EndContainer(); err != nil { // end top-level structure
		t.Fatal(err)
	}

	return append(hdrBytes, enc.Bytes()...)
}

func putCommandPathIB(t *testing.T, enc tlv.Encoder, tag uint8) {
	t.Helper()
	enc.BeginStructure(tlv.NewContextTag(tag))
	enc.PutUnsigned2(tlv.NewContextTag(0), 0)
	if err := enc.PutUnsigned(tlv.NewContextTag(1), 0x0030); err != nil {
		t.Fatal(err)
	}
	if err := enc.PutUnsigned(tlv.NewContextTag(2), 0x00); err != nil {
		t.Fatal(err)
	}
	if err := enc.EndContainer(); err != nil {
		t.Fatal(err)
	}
}

func TestParseInvokeResponseStatusSuccess(t *testing.T) {
	data := buildInvokeResponseMessage(t, func(enc tlv.Encoder) {
		enc.BeginStructure(tlv.NewAnonymousTag()) // InvokeResponseIB
		enc.BeginStructure(tlv.NewContextTag(0))  // CommandStatusIB
		putCommandPathIB(t, enc, 0)
		enc.BeginStructure(tlv.NewContextTag(1)) // StatusIB
		enc.PutUnsigned1(tlv.NewContextTag(0), 0)
		enc.PutUnsigned1(tlv.NewContextTag(1), 0)
		if err := enc.EndContainer(); err != nil { // end StatusIB
			t.Fatal(err)
		}
		if err := enc.EndContainer(); err != nil { // end CommandStatusIB
			t.Fatal(err)
		}
		if err := enc.EndContainer(); err != nil { // end InvokeResponseIB
			t.Fatal(err)
		}
	})

	resp, err := parseInvokeResponse(data)
	if err != nil {
		t.Fatalf("parseInvokeResponse() error = %v", err)
	}
	if !resp.IsSuccess() {
		t.Errorf("IsSuccess() = false, want true; status = %+v", resp.Status)
	}
}

func TestParseInvokeResponseStatusFailure(t *testing.T) {
	data := buildInvokeResponseMessage(t, func(enc tlv.Encoder) {
		enc.BeginStructure(tlv.NewAnonymousTag())
		enc.BeginStructure(tlv.NewContextTag(0))
		putCommandPathIB(t, enc, 0)
		enc.BeginStructure(tlv.NewContextTag(1))
		enc.PutUnsigned1(tlv.NewContextTag(0), 0x01) // IM status: Failure
		if err := enc.EndContainer(); err != nil {
			t.Fatal(err)
		}
		if err := enc.EndContainer(); err != nil {
			t.Fatal(err)
		}
		if err := enc.EndContainer(); err != nil {
			t.Fatal(err)
		}
	})

	resp, err := parseInvokeResponse(data)
	if err != nil {
		t.Fatalf("parseInvokeResponse() error = %v", err)
	}
	if resp.IsSuccess() {
		t.Error("IsSuccess() = true, want false")
	}
	if resp.Status.IMStatus != 0x01 {
		t.Errorf("Status.IMStatus = %#x, want 0x01", resp.Status.IMStatus)
	}
}

func TestParseInvokeResponseWithCommandDataPayload(t *testing.T) {
	data := buildInvokeResponseMessage(t, func(enc tlv.Encoder) {
		enc.BeginStructure(tlv.NewAnonymousTag()) // InvokeResponseIB
		enc.BeginStructure(tlv.NewContextTag(1))  // CommandDataIB
		putCommandPathIB(t, enc, 0)
		enc.BeginStructure(tlv.NewContextTag(1)) // CommandFields
		if err := enc.PutOctet(tlv.NewContextTag(0), []byte{0xAA, 0xBB}); err != nil {
			t.Fatal(err)
		}
		enc.PutUnsigned1(tlv.NewContextTag(1), 7)
		if err := enc.EndContainer(); err != nil { // end CommandFields
			t.Fatal(err)
		}
		if err := enc.EndContainer(); err != nil { // end CommandDataIB
			t.Fatal(err)
		}
		if err := enc.EndContainer(); err != nil { // end InvokeResponseIB
			t.Fatal(err)
		}
	})

	resp, err := parseInvokeResponse(data)
	if err != nil {
		t.Fatalf("parseInvokeResponse() error = %v", err)
	}
	if !resp.IsSuccess() {
		t.Errorf("IsSuccess() = false, want true (CommandDataIB implies success)")
	}
	field0, ok := resp.Field(0)
	if !ok {
		t.Fatal("Field(0) not found")
	}
	b, ok := field0.Bytes()
	if !ok || string(b) != "\xAA\xBB" {
		t.Errorf("Field(0).Bytes() = %v, %v; want [0xAA 0xBB], true", b, ok)
	}
	field1, ok := resp.Field(1)
	if !ok {
		t.Fatal("Field(1) not found")
	}
	v, ok := field1.Unsigned1()
	if !ok || v != 7 {
		t.Errorf("Field(1).Unsigned1() = %v, %v; want 7, true", v, ok)
	}
}

// TestBuildInvokeRequestPayloadEncodesInteractionModelRevision guards against
// a regression where the mandatory trailing InteractionModelRevision field
// (ContextTag 0xFF, spec 8.2.1) was omitted from InvokeRequestMessage, the
// same bug independently confirmed in ReadRequestMessage's encoder.
func TestBuildInvokeRequestPayloadEncodesInteractionModelRevision(t *testing.T) {
	payload, err := buildInvokeRequestPayload(0, 0x0030, 0x0002, nil)
	if err != nil {
		t.Fatalf("buildInvokeRequestPayload() error = %v", err)
	}

	dec := tlv.NewDecoderWithBytes(payload)
	if !dec.Next() || !dec.Element().Type().IsStructure() {
		t.Fatal("expected top-level Structure")
	}

	// Walk every remaining element (not just the top-level structure's
	// direct children) since the InteractionModelRevision field sits after
	// the nested invoke-requests List, whose own EndOfContainer marker must
	// be passed through, not treated as the end of the walk.
	var found bool
	for dec.Next() {
		elem := dec.Element()
		ct, ok := elem.Tag().(tlv.ContextTag)
		if !ok || ct.ContextNumber() != 0xFF {
			continue
		}
		found = true
		v, ok := elem.Unsigned1()
		if !ok || v != 12 {
			t.Errorf("InteractionModelRevision = %v, %v; want 12, true", v, ok)
		}
	}
	if err := dec.Error(); err != nil {
		t.Fatalf("decode error = %v", err)
	}
	if !found {
		t.Error("InvokeRequestMessage missing mandatory InteractionModelRevision field (tag 0xFF)")
	}
}

func TestParseInvokeResponseEmptyPayload(t *testing.T) {
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
	resp, err := parseInvokeResponse(hdrBytes)
	if err != nil {
		t.Fatalf("parseInvokeResponse() error = %v", err)
	}
	if !resp.IsSuccess() {
		t.Error("IsSuccess() = false, want true for empty payload")
	}
}
