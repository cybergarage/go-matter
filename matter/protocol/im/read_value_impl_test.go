// Copyright (C) 2026 The go-matter Authors. Licensed under the Apache License, Version 2.0.

package im

import (
	"bytes"
	"testing"

	"github.com/cybergarage/go-matter/matter/encoding/message"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
)

func closeValueFixture(t *testing.T, e tlv.Encoder, n int) {
	t.Helper()
	for range n {
		if err := e.EndContainer(); err != nil {
			t.Fatal(err)
		}
	}
}
func valueFixture(t *testing.T, put func(tlv.Encoder)) []byte {
	t.Helper()
	return withValueRevision(scalarReportFixture(t, put))
}
func withValueRevision(data []byte) []byte {
	out := bytes.Clone(data[:len(data)-1])
	return append(out, 0x24, 0xff, interactionModelRevision, 0x18)
}
func valueReportMessage(t *testing.T, put func(tlv.Encoder)) []byte {
	t.Helper()
	return withValueRevision(buildReportDataMessage(t, put))
}
func parseValueFixture(data []byte) (*ValueReadResponse, error) {
	return parseValueReadResponse(data, 1, 0xDEAD, 0x1234)
}
func TestValueReadContainersAndScalars(t *testing.T) {
	for _, kind := range []tlv.ElementType{tlv.Structure, tlv.List, tlv.Array} {
		for _, empty := range []bool{false, true} {
			data := valueFixture(t, func(e tlv.Encoder) {
				switch kind {
				case tlv.Structure:
					e.BeginStructure(tlv.NewContextTag(2))
				case tlv.List:
					e.BeginList(tlv.NewContextTag(2))
				case tlv.Array:
					e.BeginArray(tlv.NewContextTag(2))
				}
				if !empty {
					var tag tlv.Tag = tlv.NewContextTag(2)
					if kind == tlv.Array {
						tag = tlv.NewAnonymousTag()
					}
					e.BeginStructure(tag)
					e.PutUnsigned2(tlv.NewContextTag(2), 7)
					e.BeginList(tlv.NewContextTag(3))
					e.PutNull(tlv.NewContextTag(2))
					closeValueFixture(t, e, 2)
				}
				closeValueFixture(t, e, 1)
			})
			r, err := parseValueFixture(data)
			if err != nil || r.Status != nil || r.Value.Element.Type() != kind {
				t.Fatalf("%v empty=%t: %+v %v", kind, empty, r, err)
			}
			if empty {
				if len(r.Value.Children) != 0 {
					t.Fatal("empty changed")
				}
				continue
			}
			child := r.Value.Children[0]
			if child.Element.Type() != tlv.Structure || len(child.Children) != 2 {
				t.Fatal("structure flattened")
			}
			if v, ok := child.Children[0].Element.Unsigned2(); !ok || v != 7 {
				t.Fatal("inner context tag 2 lost")
			}
			if !child.Children[1].Children[0].Element.Type().IsNull() {
				t.Fatal("nested null lost")
			}
		}
	}
	for _, put := range []func(tlv.Encoder){func(e tlv.Encoder) { e.PutNull(tlv.NewContextTag(2)) }, func(e tlv.Encoder) { e.PutUnsigned2(tlv.NewContextTag(2), 42) }, func(e tlv.Encoder) { e.PutBool(tlv.NewContextTag(2), false) }} {
		data := valueFixture(t, put)
		old, err := parseReadResponse(data)
		if err != nil {
			t.Fatal(err)
		}
		r, err := parseValueFixture(data)
		if err != nil || r.Value.Element.String() != old.Value.String() {
			t.Fatalf("scalar compatibility: %+v %v", r, err)
		}
	}
}
func TestValueReadRejectsIncompleteAndInvalidResponses(t *testing.T) {
	data := valueFixture(t, func(e tlv.Encoder) {
		e.BeginStructure(tlv.NewContextTag(2))
		e.PutUnsigned2(tlv.NewContextTag(2), 7)
		closeValueFixture(t, e, 1)
	})
	for length := range data {
		if r, err := parseValueFixture(data[:length]); err == nil || r != nil {
			t.Fatalf("prefix %d became success: %+v", length, r)
		}
	}
	if r, err := parseValueFixture(append(bytes.Clone(data), 0x18)); err == nil || r != nil {
		t.Fatal("trailing bytes accepted")
	}
	if r, err := parseValueReadResponse(data, 2, 0xDEAD, 0x1234); err == nil || r != nil {
		t.Fatal("wrong path accepted")
	}
	for _, put := range []func(tlv.Encoder){
		func(e tlv.Encoder) {
			e.BeginStructure(tlv.NewContextTag(2))
			e.PutUnsigned1(tlv.NewContextTag(2), 1)
			e.PutUnsigned1(tlv.NewContextTag(2), 2)
			closeValueFixture(t, e, 1)
		},
		func(e tlv.Encoder) {
			e.BeginArray(tlv.NewContextTag(2))
			e.PutUnsigned1(tlv.NewContextTag(2), 1)
			closeValueFixture(t, e, 1)
		},
		func(e tlv.Encoder) { e.PutUnsigned1(tlv.NewContextTag(2), 1); e.PutUnsigned1(tlv.NewContextTag(2), 2) },
	} {
		if r, err := parseValueFixture(valueFixture(t, put)); err == nil || r != nil {
			t.Fatal("invalid/duplicate Data accepted")
		}
	}
	// UTF8String8 with an impossible uint64 length, not an allocation request.
	malformed := valueFixture(t, func(e tlv.Encoder) {
		if err := e.PutUTF8(tlv.NewContextTag(2), "fixture"); err != nil {
			t.Fatal(err)
		}
	})
	marker := []byte{0x2c, 2, 7}
	at := bytes.Index(malformed, marker)
	if at < 0 {
		t.Fatal("string marker missing")
	}
	malformed = append(bytes.Clone(malformed[:at]), append([]byte{0x2f, 2, 255, 255, 255, 255, 255, 255, 255, 255}, malformed[at+3:]...)...)
	if r, err := parseValueFixture(malformed); err == nil || r != nil {
		t.Fatal("invalid length accepted")
	}
}
func TestValueReadLimits(t *testing.T) {
	for _, n := range []int{MaxValueReadDepth + 1, MaxValueReadElements + 1} {
		data := valueFixture(t, func(e tlv.Encoder) {
			e.BeginList(tlv.NewContextTag(2))
			if n == MaxValueReadDepth+1 {
				for range n {
					e.BeginList(tlv.NewContextTag(2))
				}
				closeValueFixture(t, e, n)
			} else {
				for range n {
					e.PutNull(tlv.NewAnonymousTag())
				}
			}
			closeValueFixture(t, e, 1)
		})
		if r, err := parseValueFixture(data); err == nil || r != nil {
			t.Fatalf("limit %d accepted", n)
		}
	}
	data := valueFixture(t, func(e tlv.Encoder) {
		if err := e.PutOctet(tlv.NewContextTag(2), make([]byte, MaxValueReadBytes)); err != nil {
			t.Fatal(err)
		}
	})
	if r, err := parseValueFixture(data); err == nil || r != nil {
		t.Fatal("byte limit accepted")
	}
}
func valueReport(t *testing.T, e tlv.Encoder, appendItem bool, put func(tlv.Encoder)) {
	t.Helper()
	e.BeginStructure(tlv.NewAnonymousTag())
	e.BeginStructure(tlv.NewContextTag(1))
	e.BeginList(tlv.NewContextTag(1))
	e.PutUnsigned2(tlv.NewContextTag(2), 1)
	e.PutUnsigned4(tlv.NewContextTag(3), 0xDEAD)
	e.PutUnsigned4(tlv.NewContextTag(4), 0x1234)
	if appendItem {
		e.PutNull(tlv.NewContextTag(5))
	}
	closeValueFixture(t, e, 1)
	put(e)
	closeValueFixture(t, e, 2)
}
func TestValueReadAppendReportsAndStatus(t *testing.T) {
	data := valueReportMessage(t, func(e tlv.Encoder) {
		valueReport(t, e, false, func(e tlv.Encoder) { e.BeginArray(tlv.NewContextTag(2)); closeValueFixture(t, e, 1) })
		valueReport(t, e, true, func(e tlv.Encoder) {
			e.BeginStructure(tlv.NewContextTag(2))
			e.PutUnsigned2(tlv.NewContextTag(2), 7)
			closeValueFixture(t, e, 1)
		})
	})
	r, err := parseValueFixture(data)
	if err != nil || len(r.Value.Children) != 1 || r.Value.Children[0].Element.Tag().String() != tlv.NewContextTag(2).String() {
		t.Fatalf("append: %+v %v", r, err)
	}
	// A device status takes precedence over data; no partially collected value.
	data = valueReportMessage(t, func(e tlv.Encoder) {
		valueReport(t, e, false, func(e tlv.Encoder) { e.PutUnsigned2(tlv.NewContextTag(2), 7) })
		e.BeginStructure(tlv.NewAnonymousTag())
		e.BeginStructure(tlv.NewContextTag(0))
		e.BeginList(tlv.NewContextTag(0))
		e.PutUnsigned2(tlv.NewContextTag(2), 1)
		e.PutUnsigned4(tlv.NewContextTag(3), 0xDEAD)
		e.PutUnsigned4(tlv.NewContextTag(4), 0x1234)
		closeValueFixture(t, e, 1)
		e.BeginStructure(tlv.NewContextTag(1))
		e.PutUnsigned1(tlv.NewContextTag(0), uint8(StatusUnsupportedAccess))
		closeValueFixture(t, e, 3)
	})
	r, err = parseValueFixture(data)
	if err != nil || r.Status == nil || r.Value != nil || r.Status.IMStatus != uint8(StatusUnsupportedAccess) {
		t.Fatalf("status: %+v %v", r, err)
	}
	// Whole-message status (including success) has no observed Data.
	for _, code := range []uint8{0, uint8(StatusUnsupportedRead)} {
		h, err := message.NewProtocolHeader(message.WithHeaderProtocolID(message.InteractionModel), message.WithHeaderOpcode(message.StatusResponseMessage)).Bytes()
		if err != nil {
			t.Fatal(err)
		}
		e := tlv.NewEncoder()
		e.BeginStructure(tlv.NewAnonymousTag())
		e.PutUnsigned1(tlv.NewContextTag(0), code)
		e.PutUnsigned1(tlv.NewContextTag(0xff), 1)
		closeValueFixture(t, e, 1)
		h = append(h, e.Bytes()...)
		wire := h
		r, err = parseValueFixture(wire)
		if err != nil || r.Status == nil || r.Value != nil {
			t.Fatalf("status response: %+v %v", r, err)
		}
	}
}

func TestValueReadRejectsAmbiguousChunksAndMetadata(t *testing.T) {
	for _, kind := range []string{"whole-twice", "append-first", "indexed", "duplicate-path", "version-changed", "version-presence"} {
		t.Run(kind, func(t *testing.T) {
			data := valueReportMessage(t, func(e tlv.Encoder) {
				if kind != "append-first" {
					e.BeginStructure(tlv.NewAnonymousTag())
					e.BeginStructure(tlv.NewContextTag(1))
					if kind == "version-changed" || kind == "version-presence" {
						e.PutUnsigned4(tlv.NewContextTag(0), 1)
					}
					e.BeginList(tlv.NewContextTag(1))
					e.PutUnsigned2(tlv.NewContextTag(2), 1)
					e.PutUnsigned4(tlv.NewContextTag(3), 0xDEAD)
					e.PutUnsigned4(tlv.NewContextTag(4), 0x1234)
					closeValueFixture(t, e, 1)
					e.BeginArray(tlv.NewContextTag(2))
					closeValueFixture(t, e, 3)
				}
				e.BeginStructure(tlv.NewAnonymousTag())
				e.BeginStructure(tlv.NewContextTag(1))
				if kind == "version-changed" {
					e.PutUnsigned4(tlv.NewContextTag(0), 2)
				}
				e.BeginList(tlv.NewContextTag(1))
				e.PutUnsigned2(tlv.NewContextTag(2), 1)
				e.PutUnsigned4(tlv.NewContextTag(3), 0xDEAD)
				e.PutUnsigned4(tlv.NewContextTag(4), 0x1234)
				if kind == "duplicate-path" {
					e.PutUnsigned2(tlv.NewContextTag(2), 1)
				}
				if kind == "indexed" {
					e.PutUnsigned2(tlv.NewContextTag(5), 0)
				} else if kind != "whole-twice" {
					e.PutNull(tlv.NewContextTag(5))
				}
				closeValueFixture(t, e, 1)
				e.PutUnsigned2(tlv.NewContextTag(2), 7)
				closeValueFixture(t, e, 2)
			})
			if r, err := parseValueFixture(data); err == nil || r != nil {
				t.Fatalf("%s accepted: %+v", kind, r)
			}
		})
	}
	base := valueFixture(t, func(e tlv.Encoder) { e.PutUnsigned2(tlv.NewContextTag(2), 7) })
	// Alter only top-level fields, preserving the complete original reports.
	for _, suffix := range [][]byte{
		{0x29, 3, 0x24, 0xff, 12, 0x18}, // MoreChunkedMessages=true
		{0x24, 0xff, 0, 0x18},           // invalid revision
		{0x24, 0xff, 13, 0x18},          // newer revision unsupported
		{0x18},                          // absent revision
		{0x35, 5, 0x24, 2, 99, 0x18, 0x24, 0xff, 12, 0x18}, // unknown sibling with nested context 2: valid
	} {
		data := append(bytes.Clone(base[:len(base)-4]), suffix...)
		r, err := parseValueFixture(data)
		if suffix[0] == 0x35 {
			if err != nil {
				t.Fatal(err)
			}
			if n, _ := r.Value.Element.Unsigned(); n != 7 {
				t.Fatal("sibling overwrote Data")
			}
		} else if err == nil || r != nil {
			t.Fatal("invalid metadata accepted")
		}
	}
}

func TestValueReadAcceptsLimitBoundaries(t *testing.T) {
	depth := valueFixture(t, func(e tlv.Encoder) {
		e.BeginList(tlv.NewContextTag(2))
		for range MaxValueReadDepth - 4 {
			e.BeginList(tlv.NewAnonymousTag())
		}
		closeValueFixture(t, e, MaxValueReadDepth-3)
	})
	if r, err := parseValueFixture(depth); err != nil || r.Value == nil {
		t.Fatalf("allowed depth: %v", err)
	}
	elements := valueFixture(t, func(e tlv.Encoder) {
		e.BeginList(tlv.NewContextTag(2))
		for range MaxValueReadElements - 11 {
			e.PutNull(tlv.NewAnonymousTag())
		}
		closeValueFixture(t, e, 1)
	})
	if r, err := parseValueFixture(elements); err != nil || r.Value == nil {
		t.Fatalf("allowed elements: %v", err)
	}
	base := valueFixture(t, func(e tlv.Encoder) {
		if err := e.PutOctet4(tlv.NewContextTag(2), nil); err != nil {
			t.Fatal(err)
		}
	})
	exact := valueFixture(t, func(e tlv.Encoder) {
		if err := e.PutOctet4(tlv.NewContextTag(2), make([]byte, MaxValueReadBytes-len(base))); err != nil {
			t.Fatal(err)
		}
	})
	if len(exact) != MaxValueReadBytes {
		t.Fatal("wrong boundary fixture")
	}
	if r, err := parseValueFixture(exact); err != nil || r.Value == nil {
		t.Fatalf("allowed bytes: %v", err)
	}
}
