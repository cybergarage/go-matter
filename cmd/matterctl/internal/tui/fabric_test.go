// Copyright (C) 2026 The go-matter Authors. Licensed under the Apache License, Version 2.0.

package tui

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cybergarage/go-matter/matter/store"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

func TestFabricExplicitCreateRestoreAndNoOverwrite(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "new-store")
	b, err := openLiveDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("startup wrote to store")
	}
	summary, err := b.Overview()
	if err != nil || summary.Present {
		t.Fatal("unexpected identity")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := b.CreateFabric(ctx, 0xFFF1); err == nil {
		t.Fatal("canceled create succeeded")
	}
	if _, err := b.CreateFabric(context.Background(), 0); err == nil {
		t.Fatal("invalid vendor accepted")
	}
	if _, err := b.CreateFabric(context.Background(), 0xFFF1); err != nil {
		t.Fatal("isolated creation failed")
	}
	before, err := os.ReadFile(filepath.Join(dir, "fabric.json"))
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := openLiveDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	summary, err = restarted.Overview()
	if err != nil || !summary.Valid || !summary.Present || summary.Saved != 0 {
		t.Fatal("identity did not restore")
	}
	if _, err := restarted.CreateFabric(context.Background(), 0xFFF1); err == nil {
		t.Fatal("identity overwrite accepted")
	}
	after, _ := os.ReadFile(filepath.Join(dir, "fabric.json"))
	if string(before) != string(after) {
		t.Fatal("identity changed")
	}
	info, _ := os.Stat(filepath.Join(dir, "fabric.json"))
	if info.Mode().Perm() != 0600 {
		t.Fatal("identity file permissions")
	}
	rec, _, _ := restarted.st.LoadFabric()
	if strings.Contains(summary.String(), string(rec.IPK)) || strings.Contains(summary.String(), string(rec.PrivateKey)) {
		t.Fatal("summary disclosed material")
	}
	compressed, _ := fabricCompressedID(rec)
	_ = restarted.st.SaveCommissionee(store.CommissioneeRecord{NodeID: 42, FabricID: rec.FabricID, CompressedFabricID: compressed})
	_ = restarted.st.SaveCommissionee(store.CommissioneeRecord{NodeID: 42, FabricID: rec.FabricID + 1, CompressedFabricID: compressed + 1})
	ds, err := restarted.List()
	if err != nil || len(ds) != 1 {
		t.Fatal("wrong fabric inventory")
	}
}
func TestFabricFormValidationConfirmationAndCancel(t *testing.T) {
	u, s := newTestUI(t)
	u.backend = NewLive(store.NewMemStore())
	u.updateActions()
	u.fabricForm()
	_, front := u.pages.GetFrontPage()
	form := front.(*tview.Flex).GetItem(1).(*tview.Form)
	field := form.GetFormItem(0).(*tview.InputField)
	field.SetText("0")
	form.SetFocus(2)
	u.app.SetFocus(form)
	press(u, tcell.KeyEnter, 0)
	summary, _ := u.backend.(fabricBackend).Overview()
	if summary.Present || u.busy {
		t.Fatal("invalid input wrote identity")
	}
	field.SetText("0xFFF1")
	press(u, tcell.KeyEnter, 0)
	if !u.dialog || u.busy {
		t.Fatal("confirmation missing")
	}
	press(u, tcell.KeyEnter, 0) // Cancel is default.
	summary, _ = u.backend.(fabricBackend).Overview()
	if summary.Present {
		t.Fatal("cancel generated identity")
	}
	u.fabricForm()
	press(u, tcell.KeyEscape, 0)
	if u.dialog {
		t.Fatal("Esc failed")
	}
	s.SetSize(60, 24)
	u.layout(60)
}

func TestRestoredReservedVendorBlocksStartup(t *testing.T) {
	b := NewLive(store.NewMemStore())
	if _, err := b.CreateFabric(context.Background(), 0xFFF4); err != nil {
		t.Fatal(err)
	}
	r, _, err := b.st.LoadFabric()
	if err != nil {
		t.Fatal(err)
	}
	for vendor := uint16(0xFFF5); ; vendor++ {
		r.AdminVendorID = vendor
		if err := b.st.SaveFabric(r); err != nil {
			t.Fatal(err)
		}
		summary, err := b.Overview()
		if err != nil || summary.Valid {
			t.Fatal("reserved vendor marked valid")
		}
		f := &fakeCommissioner{}
		b.cmr = f
		if err := b.start(); err == nil || f.starts != 0 {
			t.Fatal("reserved vendor reached transport startup")
		}
		if vendor == 0xFFFF {
			break
		}
	}
}
