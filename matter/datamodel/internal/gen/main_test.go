// Copyright (C) 2026 The go-matter Authors. Licensed under the Apache License, Version 2.0.

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/cybergarage/go-matter/matter/datamodel"
)

func TestOfflineGenerationReproducesCatalog(t *testing.T) {
	out := filepath.Join(t.TempDir(), "catalog.json")
	if err := run("../upstream", out); err != nil {
		t.Fatal(err)
	}
	actual, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := os.ReadFile("../../catalog.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, expected) {
		t.Fatal("generated catalog differs; regenerate and review provenance")
	}
}
func TestGeneratorRejectsChangedOrUnlicensedInputs(t *testing.T) {
	dir := t.TempDir()
	entries, err := os.ReadDir("../upstream")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join("../upstream", e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, e.Name()), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(dir, "onoff-cluster.xml")
	data, _ := os.ReadFile(path)
	_ = os.WriteFile(path, append(data, ' '), 0600)
	out := filepath.Join(t.TempDir(), "catalog.json")
	if run(dir, out) == nil {
		t.Fatal("checksum change accepted")
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("failed generation published a catalog")
	}
	_ = os.WriteFile(path, data, 0600)
	manifestPath := filepath.Join(dir, "manifest.json")
	manifest, _ := os.ReadFile(manifestPath)
	var p datamodel.Provenance
	_ = json.Unmarshal(manifest, &p)
	p.Inputs[2].License = "internal-use-only"
	modified, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(manifestPath, modified, 0600)
	if run(dir, out) == nil {
		t.Fatal("unlicensed input accepted")
	}
	p.Inputs[2].License = "Apache-2.0"
	p.Inputs[2].Path = "data_model/1.6.1/clusters/DoorLock.xml"
	modified, err = json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(manifestPath, modified, 0600)
	if run(dir, out) == nil {
		t.Fatal("restricted input tree accepted")
	}
}

func TestGeneratorRequiresCompleteUniqueAuditedInputSet(t *testing.T) {
	manifest, err := os.ReadFile("../upstream/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var original datamodel.Provenance
	if err := json.Unmarshal(manifest, &original); err != nil {
		t.Fatal(err)
	}
	cases := map[string][]datamodel.Source{}
	cases["empty"] = nil
	for i, input := range original.Inputs {
		missing := append([]datamodel.Source{}, original.Inputs[:i]...)
		missing = append(missing, original.Inputs[i+1:]...)
		cases["missing-"+input.File] = missing
	}
	duplicate := append([]datamodel.Source{}, original.Inputs...)
	duplicate[0] = duplicate[1]
	cases["duplicate"] = duplicate
	unexpected := append([]datamodel.Source{}, original.Inputs...)
	unexpected[0].File = "unaudited.xml"
	cases["unexpected"] = unexpected
	for name, inputs := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			entries, err := os.ReadDir("../upstream")
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range entries {
				data, err := os.ReadFile(filepath.Join("../upstream", e.Name()))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, e.Name()), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			p := original
			p.Inputs = inputs
			data, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "manifest.json"), data, 0600); err != nil {
				t.Fatal(err)
			}
			out := filepath.Join(dir, "catalog.json")
			if run(dir, out) == nil {
				t.Fatal("invalid audited input set accepted")
			}
			if _, err := os.Stat(out); !os.IsNotExist(err) {
				t.Fatal("failed generation published catalog")
			}
		})
	}
}
