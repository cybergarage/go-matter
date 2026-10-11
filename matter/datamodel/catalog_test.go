// Copyright (C) 2026 The go-matter Authors. Licensed under the Apache License, Version 2.0.

package datamodel

import (
	"testing"

	"github.com/cybergarage/go-matter/matter/protocol/im"
)

func TestCatalogCoverageAndProvenance(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.Provenance.SDKTag != "v1.6.1.0" || c.Provenance.SourceSHA != "3bcdd56ba54fb88b2afb4bfef575014671df7aa7" || len(c.Provenance.Inputs) != 11 {
		t.Fatal("unexpected provenance")
	}
	if len(c.Clusters) != 5 || len(c.DeviceTypes) != 98 || len(c.Types) != 126 || len(c.Globals) != 5 {
		t.Fatal("coverage changed without fixture review")
	}
	if _, ok := c.Cluster(0x9999); ok {
		t.Fatal("unknown cluster invented")
	}
	if _, ok := c.DeviceType(0xDEADBEEF); ok {
		t.Fatal("unknown device type invented")
	}
	light, ok := c.DeviceType(0x0100)
	if !ok || light.Name != "On/Off Light" || light.Revision == 0 {
		t.Fatal("light profile missing")
	}
	requirements, ok := light.Definition.Child("clusters")
	if !ok || len(requirements.Children) == 0 {
		t.Fatal("device requirements lost")
	}
	orphan, ok := c.DeviceType(0xFFF10001)
	if !ok || !orphan.VendorSpecific {
		t.Fatal("test/vendor profile distinction lost")
	}
	global, ok := c.GlobalAttribute(0xFFFB)
	if !ok || global.Type != "array" || global.Definition.Property("entryType") != "attrib_id" {
		t.Fatal("global list schema lost")
	}
}
func TestOnOffSchemaDoesNotConfuseAttributeAndCommand(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	cl, ok := c.Cluster(6)
	if !ok || cl.Revision != 6 {
		t.Fatal("OnOff revision")
	}
	state, ok := cl.Attribute(0)
	if !ok || state.Type != "boolean" || state.Writable {
		t.Fatal("OnOff attribute is readonly")
	}
	for _, id := range []im.CommandID{0, 1, 2} {
		cmd, ok := cl.Command(id, "client")
		if !ok || cmd.Source != "client" {
			t.Fatal("OnOff request missing")
		}
		if _, ok := cl.Command(id, "server"); ok {
			t.Fatal("response direction invented")
		}
	}
	startup, ok := cl.Attribute(0x4003)
	if !ok || !startup.Writable || !startup.Nullable || startup.Type != "StartUpOnOffEnum" {
		t.Fatal("startup schema lost")
	}
	accesses := startup.Definition.NamedChildren("access")
	if len(accesses) != 1 || accesses[0].Property("op") != "write" || accesses[0].Property("privilege") != "manage" {
		t.Fatal("write privilege lost")
	}
	conform, ok := startup.Definition.Child("mandatoryConform")
	if !ok {
		t.Fatal("conformance lost")
	}
	feature, ok := conform.Child("feature")
	if !ok || feature.Property("name") != "LT" {
		t.Fatal("feature condition lost")
	}
	enum, ok := c.Type(startup.Type, 6)
	if !ok || enum.Kind != "enum" || len(enum.Definition.NamedChildren("item")) != 3 {
		t.Fatal("enum definition lost")
	}
	boolType, ok := c.Type("boolean", 6)
	if !ok || boolType.Definition.Property("size") != "1" {
		t.Fatal("atomic type lost")
	}
}
func TestDoorLockTimedAndTemperatureConstraintsPreserved(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	lock, _ := c.Cluster(0x0101)
	timed := false
	for _, cmd := range lock.Commands {
		if cmd.Timed {
			timed = true
		}
		for _, arg := range cmd.Definition.NamedChildren("arg") {
			if arg.Property("type") == "" {
				t.Fatal("command field type lost")
			}
		}
	}
	if !timed {
		t.Fatal("timed invoke constraint lost")
	}
	temperature, _ := c.Cluster(0x0402)
	measured, ok := temperature.Attribute(0)
	if !ok || !measured.Nullable || measured.Definition.Property("min") == "" {
		t.Fatal("temperature nullability/bounds lost")
	}
	// Load does not expose process-global mutable tables to callers.
	c.Clusters[0].Name = "changed"
	again, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if again.Clusters[0].Name == "changed" {
		t.Fatal("consumer mutation affected embedded catalog")
	}
}

func TestInventoryClusterDefinitionsAndConformanceRetention(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	descriptor, ok := c.Cluster(0x1D)
	if !ok || descriptor.Revision != 3 {
		t.Fatal("descriptor definition missing")
	}
	a, ok := descriptor.Attribute(0)
	if !ok || a.Type != "array" || a.Definition.Property("entryType") != "DeviceTypeStruct" {
		t.Fatal("device type list shape lost")
	}
	features, ok := descriptor.Definition.Child("features")
	if !ok {
		t.Fatal("feature metadata lost")
	}
	children := features.NamedChildren("feature")
	if len(children) == 0 {
		t.Fatal("descriptor features missing")
	}
	if _, ok := children[0].Child("describedConform"); !ok {
		t.Fatal("described conformance lost")
	}
	basic, ok := c.Cluster(0x28)
	if !ok || basic.Revision != 6 {
		t.Fatal("basic definition missing")
	}
	vendor, ok := basic.Attribute(1)
	if !ok || vendor.Name != "VendorName" || vendor.Type != "char_string" {
		t.Fatal("vendor definition missing")
	}
	unique, ok := basic.Attribute(18)
	if !ok {
		t.Fatal("unique ID missing")
	}
	otherwise, ok := unique.Definition.Child("otherwiseConform")
	if !ok {
		t.Fatal("revision conformance lost")
	}
	mandatory, ok := otherwise.Child("mandatoryConform")
	if !ok {
		t.Fatal("mandatory conformance lost")
	}
	if _, ok := mandatory.Child("greaterOrEqualTerm"); !ok {
		t.Fatal("revision comparison lost")
	}
}
