// Copyright (C) 2026 The go-matter Authors. Licensed under the Apache License, Version 2.0.

package zap

import (
	"strings"
	"testing"

	"github.com/cybergarage/go-matter/matter/datamodel"
)

func TestUnsupportedSchemaIsReported(t *testing.T) {
	for _, input := range []string{
		`<configurator><newConformance/></configurator>`,
		`<configurator><attribute code="1" futureConstraint="x"/></configurator>`,
		`<configurator><cluster xmlns="urn:unknown"/></configurator>`,
		`<!DOCTYPE foo><configurator/>`,
		`<configurator><cluster></configurator>`,
		`<configurator/><configurator/>`,
		`<configurator><attribute code="1" code="2"/></configurator>`,
	} {
		if _, err := Parse(strings.NewReader(input)); err == nil {
			t.Fatal("unsupported/ambiguous XML accepted")
		}
	}
}
func TestAmbiguousIndexesAndInvalidIdentityRejected(t *testing.T) {
	root, err := Parse(strings.NewReader(`<configurator><cluster><name>fixture</name><code>0x0006</code><attribute name="X" code="0x0" type="boolean" writable="maybe"/></cluster></configurator>`))
	if err != nil {
		t.Fatal(err)
	}
	c := &datamodel.Catalog{}
	if AddDocument(c, "fixture", root) == nil {
		t.Fatal("unknown boolean interpreted")
	}
	root, err = Parse(strings.NewReader(`<configurator><cluster><name>fixture</name><code>invalid</code></cluster></configurator>`))
	if err != nil {
		t.Fatal(err)
	}
	if AddDocument(&datamodel.Catalog{}, "fixture", root) == nil {
		t.Fatal("invalid ID accepted")
	}
	c = &datamodel.Catalog{Clusters: []datamodel.Cluster{{ID: 6}, {ID: 6}}}
	if Validate(c) == nil {
		t.Fatal("duplicate cluster lookup")
	}
}

func TestProcessingInstructionsRejected(t *testing.T) {
	for _, input := range []string{
		`<?future metadata?><configurator/>`,
		`<configurator><?future metadata?></configurator>`,
		`<configurator/><?future metadata?>`,
	} {
		if _, err := Parse(strings.NewReader(input)); err == nil {
			t.Fatal("unsupported processing instruction accepted")
		}
	}
	if _, err := Parse(strings.NewReader(`<?xml version="1.0" encoding="UTF-8"?><configurator/>`)); err != nil {
		t.Fatal(err)
	}
}

func TestDuplicateGlobalAttributesRejected(t *testing.T) {
	root, err := Parse(strings.NewReader(`<configurator><global><attribute code="0xFFFD" name="Revision" type="int16u"/><attribute code="65533" name="Other" type="int16u"/></global></configurator>`))
	if err != nil {
		t.Fatal(err)
	}
	c := &datamodel.Catalog{}
	if err := AddDocument(c, "fixture", root); err != nil {
		t.Fatal(err)
	}
	if Validate(c) == nil {
		t.Fatal("ambiguous global attribute lookup accepted")
	}
	c.Globals = c.Globals[:1]
	if err := Validate(c); err != nil {
		t.Fatal(err)
	}
	a, ok := c.GlobalAttribute(0xFFFD)
	if !ok || a.Name != "Revision" {
		t.Fatal("unique global lookup lost")
	}
}
