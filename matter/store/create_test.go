// Copyright (C) 2026 The go-matter Authors. Licensed under the Apache License, Version 2.0.

package store

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestCreateFabricExclusiveAndFailedSave(t *testing.T) {
	dir := t.TempDir()
	a, _ := NewStore(dir)
	b, _ := NewStore(dir)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, st := range []Store{a, b} {
		wg.Go(func() { ; results <- CreateFabric(st, FabricRecord{FabricID: 1}) })
	}
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		} else if !errors.Is(err, ErrAlreadyExists) {
			t.Fatal(err)
		}
	}
	if success != 1 {
		t.Fatal("exclusive create violated")
	}
	rec, ok, err := a.LoadFabric()
	if err != nil || !ok || rec.FabricID != 1 {
		t.Fatal("partial record")
	}
	// Block only the target path: publication fails, temp file must be removed and no record replaces it.
	dir2 := t.TempDir()
	st, _ := NewStore(dir2)
	_ = os.Mkdir(filepath.Join(dir2, "fabric.json"), 0700)
	if CreateFabric(st, FabricRecord{FabricID: 2}) == nil {
		t.Fatal("failed save hidden")
	}
	entries, _ := os.ReadDir(dir2)
	if len(entries) != 1 || !entries[0].IsDir() {
		t.Fatal("temporary identity left behind")
	}
	mem := NewMemStore()
	if CreateFabric(mem, FabricRecord{FabricID: 1}) != nil || !errors.Is(CreateFabric(mem, FabricRecord{FabricID: 2}), ErrAlreadyExists) {
		t.Fatal("memory exclusive create")
	}
}
