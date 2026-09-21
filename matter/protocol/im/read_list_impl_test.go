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

	"github.com/cybergarage/go-matter/matter/encoding/tlv"
)

// readListResponse drives parseReadResponseCore with the same dataFunc
// ReadListAttribute installs, without needing a matching Interaction Model
// exchange over a session — mirrors how read_impl_test.go's tests call
// parseReadResponse(data) directly rather than going through ReadBoolAttribute.
func readListResponse(data []byte, itemFn func(dec tlv.Decoder, item tlv.Element) error) (*InvokeStatus, error) {
	var haveContainer bool
	return parseReadResponseCore(data, func(dec tlv.Decoder, elem tlv.Element) error {
		return decodeListAttributeData(dec, elem, &haveContainer, itemFn)
	})
}

// TestReadListAttributeScalarList decodes a List-typed Data field whose
// items are plain scalars (e.g. Descriptor's ServerList/ClientList/PartsList
// — a list of ClusterID/EndpointID uint values), verifying items are
// streamed to itemFn in order.
func TestReadListAttributeScalarList(t *testing.T) {
	data := buildReportDataMessage(t, func(enc tlv.Encoder) {
		enc.BeginStructure(tlv.NewAnonymousTag()) // AttributeReportIB
		enc.BeginStructure(tlv.NewContextTag(1))  // AttributeDataIB
		enc.BeginList(tlv.NewContextTag(1))       // AttributePathIB
		enc.PutUnsigned2(tlv.NewContextTag(2), 0)
		if err := enc.EndContainer(); err != nil { // end AttributePathIB
			t.Fatal(err)
		}
		enc.BeginArray(tlv.NewContextTag(2)) // Data: List of ClusterID
		enc.PutUnsigned4(tlv.NewAnonymousTag(), 0x001D)
		enc.PutUnsigned4(tlv.NewAnonymousTag(), 0x0028)
		if err := enc.EndContainer(); err != nil { // end Data
			t.Fatal(err)
		}
		if err := enc.EndContainer(); err != nil { // end AttributeDataIB
			t.Fatal(err)
		}
		if err := enc.EndContainer(); err != nil { // end AttributeReportIB
			t.Fatal(err)
		}
	})

	var got []uint32
	status, err := readListResponse(data, func(dec tlv.Decoder, item tlv.Element) error {
		v, ok := item.Unsigned4()
		if !ok {
			t.Fatalf("item.Unsigned4() ok = false for %+v", item)
		}
		got = append(got, v)
		return nil
	})
	if err != nil {
		t.Fatalf("parseReadResponseCore() error = %v", err)
	}
	if status != nil {
		t.Fatalf("status = %+v, want nil", status)
	}
	want := []uint32{0x001D, 0x0028}
	if len(got) != len(want) {
		t.Fatalf("got %d items, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("item[%d] = %#x, want %#x", i, got[i], want[i])
		}
	}
}

// TestReadListAttributeStructList decodes a List-typed Data field whose
// items are nested Structures (Descriptor's DeviceTypeList, whose items are
// DeviceTypeStruct{DeviceType, Revision}) — itemFn must consume each item's
// own EndOfContainer itself.
func TestReadListAttributeStructList(t *testing.T) {
	data := buildReportDataMessage(t, func(enc tlv.Encoder) {
		enc.BeginStructure(tlv.NewAnonymousTag()) // AttributeReportIB
		enc.BeginStructure(tlv.NewContextTag(1))  // AttributeDataIB
		enc.BeginList(tlv.NewContextTag(1))       // AttributePathIB
		enc.PutUnsigned2(tlv.NewContextTag(2), 0)
		if err := enc.EndContainer(); err != nil { // end AttributePathIB
			t.Fatal(err)
		}
		enc.BeginArray(tlv.NewContextTag(2)) // Data: List of DeviceTypeStruct
		enc.BeginStructure(tlv.NewAnonymousTag())
		enc.PutUnsigned4(tlv.NewContextTag(0), 0x0100) // DeviceType
		enc.PutUnsigned2(tlv.NewContextTag(1), 1)      // Revision
		if err := enc.EndContainer(); err != nil {
			t.Fatal(err)
		}
		if err := enc.EndContainer(); err != nil { // end Data
			t.Fatal(err)
		}
		if err := enc.EndContainer(); err != nil { // end AttributeDataIB
			t.Fatal(err)
		}
		if err := enc.EndContainer(); err != nil { // end AttributeReportIB
			t.Fatal(err)
		}
	})

	type deviceType struct {
		DeviceType uint32
		Revision   uint16
	}
	var got []deviceType
	status, err := readListResponse(data, func(dec tlv.Decoder, item tlv.Element) error {
		if !item.Type().IsStructure() {
			t.Fatalf("item.Type() = %v, want Structure", item.Type())
		}
		var dt deviceType
		for dec.Next() {
			elem := dec.Element()
			if elem.Type().IsEndOfContainer() {
				break
			}
			ct, ok := elem.Tag().(tlv.ContextTag)
			if !ok {
				continue
			}
			switch ct.ContextNumber() {
			case 0:
				if v, ok := elem.Unsigned4(); ok {
					dt.DeviceType = v
				}
			case 1:
				if v, ok := elem.Unsigned2(); ok {
					dt.Revision = v
				}
			}
		}
		got = append(got, dt)
		return dec.Error()
	})
	if err != nil {
		t.Fatalf("parseReadResponseCore() error = %v", err)
	}
	if status != nil {
		t.Fatalf("status = %+v, want nil", status)
	}
	if len(got) != 1 {
		t.Fatalf("got %d items, want 1 (%+v)", len(got), got)
	}
	if got[0].DeviceType != 0x0100 || got[0].Revision != 1 {
		t.Errorf("got[0] = %+v, want {DeviceType:0x100 Revision:1}", got[0])
	}
}

// TestReadListAttributeChunkedList reproduces the exact wire pattern a real
// device sent for Descriptor's DeviceTypeList (10.5.4.3, "List Chunking"):
// an initiating AttributeReportIB whose Data is an empty array, immediately
// followed by a second AttributeReportIB for the same path whose
// AttributePathIB carries a null ListIndex and whose Data is the single
// appended item directly (not wrapped in another array) — which this
// client previously discarded entirely (parseAttributeReportIBsCore only
// parsed the first AttributeReportIB), making every chunked list attribute
// read back empty.
func TestReadListAttributeChunkedList(t *testing.T) {
	data := buildReportDataMessage(t, func(enc tlv.Encoder) {
		enc.BeginStructure(tlv.NewAnonymousTag()) // AttributeReportIB #1: initiate
		enc.BeginStructure(tlv.NewContextTag(1))  // AttributeDataIB
		enc.BeginList(tlv.NewContextTag(1))       // AttributePathIB
		enc.PutUnsigned2(tlv.NewContextTag(2), 0)
		if err := enc.EndContainer(); err != nil { // end AttributePathIB
			t.Fatal(err)
		}
		enc.BeginArray(tlv.NewContextTag(2)) // Data: empty array
		if err := enc.EndContainer(); err != nil {
			t.Fatal(err)
		}
		if err := enc.EndContainer(); err != nil { // end AttributeDataIB
			t.Fatal(err)
		}
		if err := enc.EndContainer(); err != nil { // end AttributeReportIB #1
			t.Fatal(err)
		}

		enc.BeginStructure(tlv.NewAnonymousTag()) // AttributeReportIB #2: append
		enc.BeginStructure(tlv.NewContextTag(1))  // AttributeDataIB
		enc.BeginList(tlv.NewContextTag(1))       // AttributePathIB
		enc.PutUnsigned2(tlv.NewContextTag(2), 0)
		enc.PutNull(tlv.NewContextTag(5)) // ListIndex: null (append)
		if err := enc.EndContainer(); err != nil {
			t.Fatal(err)
		}
		enc.BeginStructure(tlv.NewContextTag(2))       // Data: the appended item itself, not an array
		enc.PutUnsigned4(tlv.NewContextTag(0), 0x0016) // DeviceType: Root Node
		enc.PutUnsigned2(tlv.NewContextTag(1), 1)      // Revision
		if err := enc.EndContainer(); err != nil {
			t.Fatal(err)
		}
		if err := enc.EndContainer(); err != nil { // end AttributeDataIB
			t.Fatal(err)
		}
		if err := enc.EndContainer(); err != nil { // end AttributeReportIB #2
			t.Fatal(err)
		}
	})

	type deviceType struct {
		DeviceType uint32
		Revision   uint16
	}
	var got []deviceType
	status, err := readListResponse(data, func(dec tlv.Decoder, item tlv.Element) error {
		var dt deviceType
		for dec.Next() {
			elem := dec.Element()
			if elem.Type().IsEndOfContainer() {
				break
			}
			ct, ok := elem.Tag().(tlv.ContextTag)
			if !ok {
				continue
			}
			switch ct.ContextNumber() {
			case 0:
				if v, ok := elem.Unsigned4(); ok {
					dt.DeviceType = v
				}
			case 1:
				if v, ok := elem.Unsigned2(); ok {
					dt.Revision = v
				}
			}
		}
		got = append(got, dt)
		return dec.Error()
	})
	if err != nil {
		t.Fatalf("parseReadResponseCore() error = %v", err)
	}
	if status != nil {
		t.Fatalf("status = %+v, want nil", status)
	}
	if len(got) != 1 {
		t.Fatalf("got %d items, want 1 (%+v)", len(got), got)
	}
	if got[0].DeviceType != 0x0016 || got[0].Revision != 1 {
		t.Errorf("got[0] = %+v, want {DeviceType:0x16 Revision:1}", got[0])
	}
}

// TestReadListAttributeAttributeStatusError guards against itemFn being
// called when the device reports an AttributeStatusIB error for the
// requested path instead of attribute data.
func TestReadListAttributeAttributeStatusError(t *testing.T) {
	data := buildReportDataMessage(t, func(enc tlv.Encoder) {
		enc.BeginStructure(tlv.NewAnonymousTag()) // AttributeReportIB
		enc.BeginStructure(tlv.NewContextTag(0))  // AttributeStatusIB
		enc.BeginList(tlv.NewContextTag(0))       // AttributePathIB
		enc.PutUnsigned2(tlv.NewContextTag(2), 0)
		if err := enc.EndContainer(); err != nil {
			t.Fatal(err)
		}
		enc.BeginStructure(tlv.NewContextTag(1))     // StatusIB
		enc.PutUnsigned1(tlv.NewContextTag(0), 0x8b) // UnsupportedAttribute
		if err := enc.EndContainer(); err != nil {
			t.Fatal(err)
		}
		if err := enc.EndContainer(); err != nil { // end AttributeStatusIB
			t.Fatal(err)
		}
		if err := enc.EndContainer(); err != nil { // end AttributeReportIB
			t.Fatal(err)
		}
	})

	called := false
	status, err := readListResponse(data, func(dec tlv.Decoder, item tlv.Element) error {
		called = true
		return nil
	})
	if err != nil {
		t.Fatalf("parseReadResponseCore() error = %v", err)
	}
	if status == nil {
		t.Fatal("status = nil, want non-nil for an AttributeStatusIB report")
	}
	if status.IMStatus != 0x8b {
		t.Errorf("status.IMStatus = %#x, want 0x8b", status.IMStatus)
	}
	if called {
		t.Error("itemFn was called, want it skipped for a status report")
	}
}
