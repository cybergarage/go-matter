// Copyright (C) 2026 The go-matter Authors. Licensed under the Apache License, Version 2.0.

package tui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/cybergarage/go-matter/matter"
	"github.com/cybergarage/go-matter/matter/config"
	"github.com/cybergarage/go-matter/matter/store"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// fixturePassword is a fictional Wi-Fi password for the tests.
const fixturePassword = "fixture-passphrase"

func TestParseWiFi(t *testing.T) {
	if w, err := ParseWiFi("", ""); w != nil || err != nil {
		t.Fatal("both fields empty must mean no Wi-Fi")
	}
	w, err := ParseWiFi("home-ap", fixturePassword)
	if err != nil || string(w.SSID) != "home-ap" || string(w.Password) != fixturePassword {
		t.Fatalf("valid Wi-Fi rejected: %v", err)
	}
	if _, err := ParseWiFi("home-ap", strings.Repeat("a", 64)); err == nil {
		t.Fatal("a 64-character passphrase which is no hexadecimal PSK accepted")
	}
	if _, err := ParseWiFi("home-ap", strings.Repeat("ab", 32)); err != nil {
		t.Fatalf("a 64-hex-digit PSK rejected: %v", err)
	}
	for _, c := range []struct{ ssid, password string }{
		{"", fixturePassword},
		{"home-ap", ""},
		{strings.Repeat("s", 33), fixturePassword},
		{"home-ap", "short"},
		{"home-ap", strings.Repeat("p", 65)},
	} {
		_, err := ParseWiFi(c.ssid, c.password)
		if err == nil {
			t.Fatalf("ParseWiFi(%q, %q) accepted", c.ssid, c.password)
		}
		if c.password != "" && strings.Contains(err.Error(), c.password) {
			t.Fatal("an error echoed the password")
		}
	}
}

func TestLivePairGivesWiFiToTheCommissioner(t *testing.T) {
	st, err := store.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	seedStore(t, st)
	b := NewLive(st)
	f := &fakeCommissioner{st: b.st}
	b.cmr = f
	p, _ := ParsePayload(fixtureCode)

	if _, err := b.Pair(context.Background(), p, nil); err != nil {
		t.Fatal(err)
	}
	for _, opt := range f.opts {
		if _, ok := opt.(config.WiFiNetworkConfig); ok {
			t.Fatal("Wi-Fi given without credentials")
		}
	}

	f.err = fmt.Errorf("%w: found over BLE only: %w", matter.ErrNotFound, matter.ErrWiFiNetworkRequired)
	_, err = b.Pair(context.Background(), p, nil)
	if err == nil || !strings.Contains(err.Error(), "Wi-Fi SSID and password") {
		t.Fatalf("a BLE-only device must ask for Wi-Fi: %v", err)
	}

	f.err = nil
	if _, err := b.Pair(context.Background(), p, &WiFiCredentials{SSID: []byte("home-ap"), Password: []byte(fixturePassword)}); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	var wifi config.WiFiNetworkConfig
	for _, opt := range f.opts {
		if w, ok := opt.(config.WiFiNetworkConfig); ok {
			wifi = w
		}
	}
	if wifi == nil {
		t.Fatal("Wi-Fi credentials not given to the commissioner")
	}
	ssid, _ := wifi.SSID()
	password, _ := wifi.Credentials()
	if string(ssid) != "home-ap" || string(password) != fixturePassword {
		t.Fatal("Wi-Fi credentials changed on the way")
	}
}

func TestPairFormWiFiFields(t *testing.T) {
	u, s := newTestUI(t)
	u.pairForm()
	_, front := u.pages.GetFrontPage()
	form := front.(*tview.Flex).GetItem(1).(*tview.Form)
	if form.GetFormItemCount() != 3 {
		t.Fatalf("pair form has %d fields, want code, SSID and password", form.GetFormItemCount())
	}
	code := form.GetFormItem(0).(*tview.InputField)
	ssid := form.GetFormItem(1).(*tview.InputField)
	password := form.GetFormItem(2).(*tview.InputField)
	code.SetText(fixtureCode)
	ssid.SetText("home-ap")
	password.SetText(fixturePassword)

	w, h := s.Size()
	u.pages.SetRect(0, 0, w, h)
	u.pages.Draw(s)
	var screen strings.Builder
	for y := range h {
		for x := range w {
			r, _, _, _ := s.GetContent(x, y)
			screen.WriteRune(r)
		}
	}
	if strings.Contains(screen.String(), fixturePassword) || !strings.Contains(screen.String(), "home-ap") {
		t.Fatal("the password must be masked, and the SSID shown")
	}

	// A password without an SSID stays in the form.
	ssid.SetText("")
	form.SetFocus(3)
	u.app.SetFocus(form)
	press(u, tcell.KeyEnter, 0)
	if _, front = u.pages.GetFrontPage(); !u.dialog || u.busy {
		t.Fatal("invalid Wi-Fi left the form")
	}
	if _, ok := front.(*tview.Modal); ok {
		t.Fatal("invalid Wi-Fi reached the confirmation")
	}

	// Valid Wi-Fi leads to a confirmation which names the SSID only.
	ssid.SetText("home-ap")
	press(u, tcell.KeyEnter, 0)
	_, front = u.pages.GetFrontPage()
	if _, ok := front.(*tview.Modal); !ok {
		t.Fatal("valid Wi-Fi must lead to the confirmation")
	}
	if password.GetText() != "" || ssid.GetText() != "" || code.GetText() != "" {
		t.Fatal("the form kept its values after validation")
	}
	press(u, tcell.KeyEscape, 0)
}
