// Copyright (C) 2026 The go-matter Authors. Licensed under the Apache License, Version 2.0.

package im

import (
	"errors"
	"testing"

	"github.com/cybergarage/go-matter/matter/encoding/tlv"
)

func scalarReportFixture(t *testing.T, put func(tlv.Encoder)) []byte {
	t.Helper()
	return buildReportDataMessage(t, func(e tlv.Encoder) {
		e.BeginStructure(tlv.NewAnonymousTag())
		e.BeginStructure(tlv.NewContextTag(1))
		e.BeginList(tlv.NewContextTag(1))
		e.PutUnsigned2(tlv.NewContextTag(2), 1)
		e.PutUnsigned4(tlv.NewContextTag(3), 0xDEAD)
		e.PutUnsigned4(tlv.NewContextTag(4), 0x1234)
		if err := e.EndContainer(); err != nil {
			t.Fatal(err)
		}
		put(e)
		for i := 0; i < 2; i++ {
			if err := e.EndContainer(); err != nil {
				t.Fatal(err)
			}
		}
	})
}

func TestScalarReadRejectsContainerDataWithNestedTag2(t *testing.T) {
	for _, kind := range []string{"structure", "nested-structure", "list", "array"} {
		t.Run(kind, func(t *testing.T) {
			data := scalarReportFixture(t, func(e tlv.Encoder) {
				switch kind {
				case "structure", "nested-structure":
					e.BeginStructure(tlv.NewContextTag(2))
				case "list":
					e.BeginList(tlv.NewContextTag(2))
				case "array":
					e.BeginArray(tlv.NewContextTag(2))
				}
				if kind == "structure" {
					// CapabilityMinimaStruct: fieldId 2 is SimultaneousInvocationsSupported.
					e.PutUnsigned2(tlv.NewContextTag(0), 1)
					e.PutUnsigned2(tlv.NewContextTag(1), 2)
					e.PutUnsigned2(tlv.NewContextTag(2), 7)
				} else {
					var itemTag tlv.Tag = tlv.NewContextTag(0)
					var numberTag tlv.Tag = tlv.NewContextTag(2)
					if kind == "array" {
						itemTag = tlv.NewAnonymousTag()
						numberTag = tlv.NewAnonymousTag()
					}
					e.BeginStructure(itemTag)
					e.PutUnsigned2(tlv.NewContextTag(2), 7)
					if err := e.EndContainer(); err != nil {
						t.Fatal(err)
					}
					e.PutUnsigned2(numberTag, 9)
				}
				if err := e.EndContainer(); err != nil {
					t.Fatal(err)
				}
			})
			response, err := parseReadResponse(data)
			if !errors.Is(err, ErrNonScalarAttribute) || response != nil {
				t.Fatalf("container became scalar: response=%+v error=%v", response, err)
			}
		})
	}
}

func TestScalarReadRejectsEmptyContainersAndMalformedScalar(t *testing.T) {
	for _, begin := range []func(tlv.Encoder){
		func(e tlv.Encoder) { e.BeginStructure(tlv.NewContextTag(2)) },
		func(e tlv.Encoder) { e.BeginList(tlv.NewContextTag(2)) },
		func(e tlv.Encoder) { e.BeginArray(tlv.NewContextTag(2)) },
	} {
		data := scalarReportFixture(t, func(e tlv.Encoder) {
			begin(e)
			if err := e.EndContainer(); err != nil {
				t.Fatal(err)
			}
		})
		response, err := parseReadResponse(data)
		if !errors.Is(err, ErrNonScalarAttribute) || response != nil {
			t.Fatalf("empty container accepted: %+v %v", response, err)
		}
	}
	data := scalarReportFixture(t, func(e tlv.Encoder) {
		if err := e.PutUTF8(tlv.NewContextTag(2), "fixture"); err != nil {
			t.Fatal(err)
		}
	})
	// Remove all six enclosing/footer bytes plus the final string byte.
	response, err := parseReadResponse(data[:len(data)-7])
	if err == nil || response != nil {
		t.Fatalf("truncated scalar accepted: %+v %v", response, err)
	}
}

func TestScalarReadKeepsScalarNullAndSkipsNestedSiblingTags(t *testing.T) {
	for _, null := range []bool{false, true} {
		data := scalarReportFixture(t, func(e tlv.Encoder) {
			if null {
				e.PutNull(tlv.NewContextTag(2))
			} else {
				e.PutUnsigned2(tlv.NewContextTag(2), 42)
			}
			e.BeginStructure(tlv.NewContextTag(3)) // Unknown sibling field, not Data.
			e.BeginList(tlv.NewContextTag(2))
			e.PutUnsigned2(tlv.NewContextTag(2), 99)
			for i := 0; i < 2; i++ {
				if err := e.EndContainer(); err != nil {
					t.Fatal(err)
				}
			}
		})
		response, err := parseReadResponse(data)
		if err != nil || response.Status != nil || response.Value == nil {
			t.Fatalf("scalar lost: %+v %v", response, err)
		}
		if null {
			if !response.Value.Type().IsNull() {
				t.Fatal("null overwritten")
			}
		} else if value, ok := response.Value.Unsigned2(); !ok || value != 42 {
			t.Fatal("nested sibling overwrote scalar")
		}
	}
}
