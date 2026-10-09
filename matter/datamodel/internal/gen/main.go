// Copyright (C) 2026 The go-matter Authors. Licensed under the Apache License, Version 2.0.

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cybergarage/go-matter/matter/datamodel"
	"github.com/cybergarage/go-matter/matter/datamodel/internal/zap"
)

const sourceSHA = "3bcdd56ba54fb88b2afb4bfef575014671df7aa7"

func main() {
	input := flag.String("input", "internal/upstream", "audited offline input directory")
	output := flag.String("output", "catalog.json", "generated catalog")
	flag.Parse()
	if err := run(*input, *output); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(input, output string) error {
	data, err := os.ReadFile(filepath.Join(input, "manifest.json"))
	if err != nil {
		return err
	}
	var p datamodel.Provenance
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	if p.SourceSHA != sourceSHA || p.SDKTag != "v1.6.1.0" || p.GeneratorVersion != "1" {
		return errors.New("unsupported provenance; audit source and generator version before changing")
	}
	zclData, err := os.ReadFile(filepath.Join(input, "zcl.json"))
	if err != nil {
		return err
	}
	var zcl struct {
		XMLFile []string `json:"xmlFile"`
	}
	if err := json.Unmarshal(zclData, &zcl); err != nil {
		return err
	}
	catalog := datamodel.Catalog{Provenance: p}
	for _, source := range p.Inputs {
		if filepath.Base(source.File) != source.File || source.License != "Apache-2.0" {
			return errors.New("unsupported input/license")
		}
		expected := "src/app/zap-templates/zcl/data-model/chip/" + source.File
		switch source.File {
		case "LICENSE":
			expected = "LICENSE"
		case "zcl.json":
			expected = "src/app/zap-templates/zcl/zcl.json"
		}
		if source.Path != expected {
			return errors.New("input outside audited SDK ZAP tree")
		}
		data, err := os.ReadFile(filepath.Join(input, source.File))
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != source.SHA256 {
			return fmt.Errorf("input checksum mismatch: %s", source.File)
		}
		if !strings.HasSuffix(source.File, ".xml") {
			continue
		}
		listed := false
		for _, name := range zcl.XMLFile {
			if name == source.File {
				listed = true
			}
		}
		if !listed {
			return errors.New("XML is absent from SDK manifest")
		}
		if !bytes.Contains(data, []byte("Licensed under the Apache License, Version 2.0")) {
			return errors.New("individual XML Apache notice missing")
		}
		root, err := zap.Parse(bytes.NewReader(data))
		if err != nil {
			return fmt.Errorf("%s: %w", source.File, err)
		}
		if err := zap.AddDocument(&catalog, source.File, root); err != nil {
			return fmt.Errorf("%s: %w", source.File, err)
		}
	}
	if err := zap.Validate(&catalog); err != nil {
		return err
	}
	data, err = json.MarshalIndent(catalog, "", "  ")
	if err != nil {
		return err
	}
	// Public metadata contains no credential material.
	return os.WriteFile(output, append(data, '\n'), 0644) //nolint:gosec
}
