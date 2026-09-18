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

// TestBuildReadRequestPayloadOmitsWildcardFields guards against a regression
// where the AttributePathIB explicitly encoded Node=0 and ListIndex=0 (and a
// spurious, undefined tag 6) instead of omitting them. Per 10.6.2, an
// AttributePathIB's Node and ListIndex fields mean "wildcard" only when
// absent; a present ListIndex on a path whose attribute is not list-typed is
// a malformed request, and a real device rejected it (returning no matching
// attribute report) rather than the requested boolean attribute value.
func TestBuildReadRequestPayloadOmitsWildcardFields(t *testing.T) {
	payload, err := buildReadRequestPayload(0, 0x0030, 0x0003)
	if err != nil {
		t.Fatalf("buildReadRequestPayload() error = %v", err)
	}

	dec := tlv.NewDecoderWithBytes(payload)
	if !dec.Next() || !dec.Element().Type().IsStructure() {
		t.Fatal("expected top-level Structure")
	}
	if !dec.Next() || !dec.Element().Type().IsArray() {
		t.Fatal("expected attribute-requests Array")
	}
	if !dec.Next() || !dec.Element().Type().IsList() {
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
	if err := dec.Error(); err != nil {
		t.Fatalf("decode error = %v", err)
	}

	for _, tag := range []uint8{0, 1, 5, 6} {
		if _, ok := seen[tag]; ok {
			t.Errorf("AttributePathIB unexpectedly encodes tag %d (must be omitted, not zero)", tag)
		}
	}

	endpoint, ok := seen[2]
	if !ok {
		t.Fatal("AttributePathIB missing Endpoint (tag 2)")
	}
	if v, ok := endpoint.Unsigned2(); !ok || v != 0 {
		t.Errorf("Endpoint = %v, %v; want 0, true", v, ok)
	}

	cluster, ok := seen[3]
	if !ok {
		t.Fatal("AttributePathIB missing Cluster (tag 3)")
	}
	if v, ok := cluster.Unsigned4(); !ok || v != 0x0030 {
		t.Errorf("Cluster = %#x, %v; want 0x30, true", v, ok)
	}

	attribute, ok := seen[4]
	if !ok {
		t.Fatal("AttributePathIB missing Attribute (tag 4)")
	}
	if v, ok := attribute.Unsigned4(); !ok || v != 0x0003 {
		t.Errorf("Attribute = %#x, %v; want 0x3, true", v, ok)
	}
}

func buildReportDataMessage(t *testing.T, buildReports func(enc tlv.Encoder)) []byte {
	t.Helper()
	hdr := message.NewProtocolHeader(
		message.WithHeaderExchangeFlags(message.ReliabilityFlag),
		message.WithHeaderOpcode(message.ReportDataMessage),
		message.WithHeaderExchangeID(message.NewFirstExchangeID()),
		message.WithHeaderProtocolID(message.InteractionModel),
	)
	hdrBytes, err := hdr.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	enc.BeginArray(tlv.NewContextTag(1)) // attribute-report-IBs
	buildReports(enc)
	if err := enc.EndContainer(); err != nil { // end attribute-report-IBs
		t.Fatal(err)
	}
	enc.PutBool(tlv.NewContextTag(4), false) // suppress-response
	if err := enc.EndContainer(); err != nil {
		t.Fatal(err)
	}

	return append(hdrBytes, enc.Bytes()...)
}

func TestParseReadResponseAttributeDataSuccess(t *testing.T) {
	data := buildReportDataMessage(t, func(enc tlv.Encoder) {
		enc.BeginStructure(tlv.NewAnonymousTag()) // AttributeReportIB
		enc.BeginStructure(tlv.NewContextTag(1))  // AttributeDataIB
		enc.PutUnsigned1(tlv.NewContextTag(0), 1) // DataVersion
		enc.BeginList(tlv.NewContextTag(1))       // AttributePathIB
		enc.PutUnsigned2(tlv.NewContextTag(2), 0)
		if err := enc.EndContainer(); err != nil { // end AttributePathIB
			t.Fatal(err)
		}
		enc.PutBool(tlv.NewContextTag(2), true) // Data
		if err := enc.EndContainer(); err != nil {
			t.Fatal(err)
		}
		if err := enc.EndContainer(); err != nil {
			t.Fatal(err)
		}
	})

	resp, err := parseReadResponse(data)
	if err != nil {
		t.Fatalf("parseReadResponse() error = %v", err)
	}
	if resp.Status != nil {
		t.Fatalf("Status = %+v, want nil", resp.Status)
	}
	if resp.Value == nil {
		t.Fatal("Value = nil, want a Bool element")
	}
	v, ok := resp.Value.Bool()
	if !ok || !v {
		t.Errorf("Value.Bool() = %v, %v; want true, true", v, ok)
	}
}

func TestParseReadResponseAttributeStatusError(t *testing.T) {
	data := buildReportDataMessage(t, func(enc tlv.Encoder) {
		enc.BeginStructure(tlv.NewAnonymousTag()) // AttributeReportIB
		enc.BeginStructure(tlv.NewContextTag(0))  // AttributeStatusIB
		enc.BeginList(tlv.NewContextTag(0))       // AttributePathIB
		enc.PutUnsigned2(tlv.NewContextTag(2), 0)
		if err := enc.EndContainer(); err != nil { // end AttributePathIB
			t.Fatal(err)
		}
		enc.BeginStructure(tlv.NewContextTag(1))     // StatusIB
		enc.PutUnsigned1(tlv.NewContextTag(0), 0x8b) // UnsupportedAttribute
		if err := enc.EndContainer(); err != nil {   // end StatusIB
			t.Fatal(err)
		}
		if err := enc.EndContainer(); err != nil { // end AttributeStatusIB
			t.Fatal(err)
		}
		if err := enc.EndContainer(); err != nil { // end AttributeReportIB
			t.Fatal(err)
		}
	})

	resp, err := parseReadResponse(data)
	if err != nil {
		t.Fatalf("parseReadResponse() error = %v", err)
	}
	if resp.Status == nil {
		t.Fatal("Status = nil, want non-nil for an AttributeStatusIB report")
	}
	if resp.Status.IMStatus != 0x8b {
		t.Errorf("Status.IMStatus = %#x, want 0x8b", resp.Status.IMStatus)
	}
	if resp.Value != nil {
		t.Errorf("Value = %+v, want nil for an AttributeStatusIB report", resp.Value)
	}
}
