// Copyright (C) 2026 The go-matter Authors. Licensed under the Apache License, Version 2.0.

package datamodel

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

//go:generate go run ./internal/gen -input internal/upstream -output catalog.json

//go:embed catalog.json
var embedded []byte

// Load returns an independent catalog from the embedded audited snapshot.
// It performs no network, credential, store or hardware operation.
func Load() (*Catalog, error) {
	return Decode(embedded)
}

// Decode reads the language-independent catalog contract and rejects incompatible schemas.
func Decode(data []byte) (*Catalog, error) {
	var header struct {
		SchemaVersion int `json:"schemaVersion"`
	}
	if err := json.Unmarshal(data, &header); err != nil {
		return nil, err
	}
	if header.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("unsupported Matter catalog schemaVersion: %d", header.SchemaVersion)
	}
	var c Catalog
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	return &c, nil
}
