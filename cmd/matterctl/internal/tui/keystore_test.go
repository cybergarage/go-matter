// Copyright (C) 2026 The go-matter Authors. Licensed under the Apache License, Version 2.0.

package tui

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/cybergarage/go-matter/matter"
	"github.com/cybergarage/go-matter/matter/keystore"
)

func TestFabricCreatedInAKeyStore(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	keys := filepath.Join(t.TempDir(), "keys")
	ks, err := keystore.NewFileKeyStore(keys, keystore.WithPassphrase([]byte("tui test")))
	if err != nil {
		t.Fatal(err)
	}
	b, err := openLiveDirectoryWithKeyStore(dir, ks)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.CreateFabric(context.Background(), 0xFFF1); err != nil {
		t.Fatalf("CreateFabric() error = %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "fabric.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("rivateKey")) {
		t.Fatal("the fabric record holds a private key")
	}
	for _, name := range []string{matter.RootKeyName, matter.OperationalKeyName} {
		if _, err := ks.Signer(name); err != nil {
			t.Fatalf("the key store has no %s key: %v", name, err)
		}
	}

	reopened, err := keystore.NewFileKeyStore(keys, keystore.WithPassphrase([]byte("tui test")))
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := openLiveDirectoryWithKeyStore(dir, reopened)
	if err != nil {
		t.Fatal(err)
	}
	if summary, err := restarted.Overview(); err != nil || !summary.Valid {
		t.Fatalf("Overview() = %+v, %v; want a valid fabric", summary, err)
	}
	// Without its key store, the fabric is not usable.
	without, err := openLiveDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	if summary, _ := without.Overview(); summary.Valid {
		t.Fatal("a fabric whose keys are in a key store is valid without it")
	}
	// A second fabric is not created over the key store's keys.
	other, err := openLiveDirectoryWithKeyStore(filepath.Join(t.TempDir(), "other"), reopened)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.CreateFabric(context.Background(), 0xFFF1); err == nil {
		t.Fatal("a fabric was created over the key store's keys")
	}
	if _, err := reopened.Signer(matter.RootKeyName); err != nil {
		t.Fatal("a refused creation removed the key store's key")
	}
}
