// Copyright (C) 2026 The go-matter Authors. Licensed under the Apache License, Version 2.0.

package datamodel

import (
	_ "embed"
	"encoding/json"
)

//go:generate go run ./internal/gen -input internal/upstream -output catalog.json

//go:embed catalog.json
var embedded []byte

// Load returns an independent catalog from the embedded audited snapshot.
// It performs no network, credential, store or hardware operation.
func Load() (*Catalog, error) {
	var c Catalog
	if err := json.Unmarshal(embedded, &c); err != nil {
		return nil, err
	}
	return &c, nil
}
