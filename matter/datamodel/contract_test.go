// Copyright (C) 2026 The go-matter Authors. Licensed under the Apache License, Version 2.0.

package datamodel

import (
	"encoding/json"
	"os"
	"testing"
)

// The identical fixture is consumed by ConciergeCoreTests in homekit-ios.
func TestSwiftGoldenContract(t *testing.T) {
	data, err := os.ReadFile("testdata/swift-golden.json")
	if err != nil {
		t.Fatal(err)
	}
	c, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	cluster, ok := c.Cluster(6)
	if !ok || cluster.Name != "On/Off" || cluster.Revision != 6 {
		t.Fatal("cluster mismatch")
	}
	a, ok := c.Attribute(0, 6)
	if !ok || a.Name != "OnOff" || a.Writable {
		t.Fatal("local attribute mismatch")
	}
	a, ok = c.GlobalAttribute(0)
	if !ok || a.Name != "GlobalCollision" {
		t.Fatal("global mismatch")
	}
	typ, ok := c.Type("ScopeTest", 6)
	if !ok || typ.Definition.Text != "cluster" {
		t.Fatal("cluster type must win")
	}
	typ, ok = c.Type("ScopeTest", 999)
	if !ok || typ.Definition.Text != "global" {
		t.Fatal("global type fallback")
	}
	if _, ok = c.Cluster(0xFFFF); ok {
		t.Fatal("unknown cluster resolved")
	}
	command, ok := cluster.Command(1, "client")
	if !ok || command.Name != "On" {
		t.Fatal("command mismatch")
	}
	if _, ok = cluster.Command(1, "server"); ok {
		t.Fatal("wrong command direction")
	}
	refs, exists := c.DeviceTypes[0].Definition.Child("clusters")
	if !exists || refs.NamedChildren("include")[0].Property("cluster") != "Identify" {
		t.Fatal("unresolved Identify reference lost")
	}
	if len(c.DeviceTypes[0].Definition.Children) == 0 {
		t.Fatal("unresolved profile tree lost")
	}
}

func TestDecodeSchemaVersion(t *testing.T) {
	for _, input := range []string{`{}`, `{"schemaVersion":2}`, `{"schemaVersion":"1"}`, `null`} {
		if _, err := Decode([]byte(input)); err == nil {
			t.Fatalf("accepted incompatible schema: %s", input)
		}
	}
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(data); err != nil {
		t.Fatal(err)
	}
}
