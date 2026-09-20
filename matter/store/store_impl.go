// Copyright (C) 2026 The go-matter Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	// dirMode is deliberately restrictive: fabric.json and every
	// commissionee record hold private key material in plaintext.
	dirMode  = 0o700
	fileMode = 0o600

	fabricFileName         = "fabric.json"
	commissioneesDirName   = "commissions"
	commissioneeFileGlob   = "*.json"
	commissioneeFileLayout = "%016X-%016X.json"
)

type fileStore struct {
	dir             string
	commissioneeDir string
}

// NewStore returns a Store rooted at dir, creating dir and its
// "commissions" subdirectory (both at 0700) if they don't already exist.
func NewStore(dir string) (Store, error) {
	if dir == "" {
		return nil, fmt.Errorf("store: directory is required")
	}
	commissioneeDir := filepath.Join(dir, commissioneesDirName)
	if err := os.MkdirAll(commissioneeDir, dirMode); err != nil {
		return nil, fmt.Errorf("store: create %s: %w", commissioneeDir, err)
	}
	return &fileStore{dir: dir, commissioneeDir: commissioneeDir}, nil
}

func (s *fileStore) Dir() string {
	return s.dir
}

func (s *fileStore) SaveFabric(rec FabricRecord) error {
	return writeJSONFile(filepath.Join(s.dir, fabricFileName), rec)
}

func (s *fileStore) LoadFabric() (FabricRecord, bool, error) {
	var rec FabricRecord
	ok, err := readJSONFile(filepath.Join(s.dir, fabricFileName), &rec)
	return rec, ok, err
}

func (s *fileStore) SaveCommissionee(rec CommissioneeRecord) error {
	path := filepath.Join(s.commissioneeDir, commissioneeFileName(rec.CompressedFabricID, rec.NodeID))
	return writeJSONFile(path, rec)
}

func (s *fileStore) LoadCommissionee(compressedFabricID, nodeID uint64) (CommissioneeRecord, bool, error) {
	var rec CommissioneeRecord
	path := filepath.Join(s.commissioneeDir, commissioneeFileName(compressedFabricID, nodeID))
	ok, err := readJSONFile(path, &rec)
	return rec, ok, err
}

func (s *fileStore) ListCommissionees() ([]CommissioneeRecord, error) {
	matches, err := filepath.Glob(filepath.Join(s.commissioneeDir, commissioneeFileGlob))
	if err != nil {
		return nil, fmt.Errorf("store: list %s: %w", s.commissioneeDir, err)
	}
	recs := make([]CommissioneeRecord, 0, len(matches))
	for _, path := range matches {
		var rec CommissioneeRecord
		ok, err := readJSONFile(path, &rec)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		recs = append(recs, rec)
	}
	return recs, nil
}

func commissioneeFileName(compressedFabricID, nodeID uint64) string {
	return fmt.Sprintf(commissioneeFileLayout, compressedFabricID, nodeID)
}

func writeJSONFile(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("store: marshal %s: %w", path, err)
	}
	if err := os.WriteFile(path, b, fileMode); err != nil {
		return fmt.Errorf("store: write %s: %w", path, err)
	}
	return nil
}

func readJSONFile(path string, v any) (bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("store: read %s: %w", path, err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		return false, fmt.Errorf("store: unmarshal %s: %w", path, err)
	}
	return true, nil
}
