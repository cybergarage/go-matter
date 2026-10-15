// Copyright (C) 2026 The go-matter Authors. Licensed under the Apache License, Version 2.0.

package tui

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cybergarage/go-logger/log"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

func TestParseLogLevel(t *testing.T) {
	cases := []struct {
		in   string
		want LogLevel
	}{{"", LogOff}, {"off", LogOff}, {"INFO", LogInfo}, {" debug ", LogDebug}}
	for _, c := range cases {
		s, want := c.in, c.want
		got, err := ParseLogLevel(s)
		if err != nil || got != want {
			t.Fatalf("ParseLogLevel(%q) = %v, %v; want %v", s, got, err, want)
		}
	}
	if _, err := ParseLogLevel("trace"); err == nil {
		t.Fatal("unknown level accepted")
	}
}

func TestLogSinkWritesFileAndReadsItBack(t *testing.T) {
	t.Cleanup(func() { log.SetDefault(nil) })
	path := filepath.Join(t.TempDir(), DefaultLogFileName(time.Now()))
	sink := &logSink{}
	if err := sink.Enable(LogInfo, path); err != nil {
		t.Fatal(err)
	}
	tuiLogf("first line")
	log.Debugf("not at info level")
	text, err := sink.ReadNew()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "matterctl tui: log level INFO") || !strings.Contains(text, "tui: first line") {
		t.Fatalf("log file lacks the lines written: %q", text)
	}
	if strings.Contains(text, "not at info level") {
		t.Fatal("a debug line was written at info level")
	}
	tuiLogErrorf("second line")
	text, err = sink.ReadNew()
	if err != nil || strings.Contains(text, "first line") || !strings.Contains(text, "tui: second line") {
		t.Fatalf("ReadNew must return only the new lines: %q, %v", text, err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != logFileMode {
			t.Fatalf("log file mode %v, want %v", info.Mode().Perm(), os.FileMode(logFileMode))
		}
	}
	sink.Disable()
	if log.Default() != nil {
		t.Fatal("Disable left the library logging")
	}
	if sink.Path() != path {
		t.Fatal("Disable must keep the file for the panel")
	}
}

func TestLogFileKeepsItsModeWhenItExists(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no Unix file modes")
	}
	t.Cleanup(func() { log.SetDefault(nil) })
	path := filepath.Join(t.TempDir(), "existing.log")
	if err := os.WriteFile(path, []byte("earlier\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sink := &logSink{}
	if err := sink.Enable(LogDebug, path); err != nil {
		t.Fatal(err)
	}
	sink.Disable()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != logFileMode {
		t.Fatalf("existing log file left at %v", info.Mode().Perm())
	}
}

func TestLogFromMenuShowsPanelAndOperations(t *testing.T) {
	t.Cleanup(func() { log.SetDefault(nil) })
	s := tcell.NewSimulationScreen("UTF-8")
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	s.SetSize(110, 32)
	dir := t.TempDir()
	u := newUIWithLog(&Demo{}, "OFFLINE FIXTURE — fictional devices / no network", s, &logSink{}, dir)
	t.Cleanup(func() { u.rootCancel(); s.Fini() })
	if u.root.GetItemCount() != 3 {
		t.Fatal("no log panel is shown before the log is turned on")
	}
	if !strings.Contains(u.status.GetText(false), "LOG: OFF") {
		t.Fatal("status must tell the log is off")
	}

	u.logForm()
	_, front := u.pages.GetFrontPage()
	if _, ok := front.(*tview.Modal); !ok || !u.dialog {
		t.Fatal("log level dialog missing")
	}
	press(u, tcell.KeyEnter, 0) // Cancel has the focus.
	if u.logs.Level() != LogOff {
		t.Fatal("Enter on the log dialog must change nothing")
	}

	u.setLogLevel(LogInfo)
	matches, _ := filepath.Glob(filepath.Join(dir, "matterctl-*.log"))
	if len(matches) != 1 || u.logs.Path() != matches[0] {
		t.Fatalf("log file not created in the start directory: %v", matches)
	}
	if u.root.GetItemCount() != 4 {
		t.Fatal("log panel not shown")
	}
	if !strings.Contains(u.status.GetText(false), "LOG: INFO") {
		t.Fatal("status must tell the log level")
	}

	u.startOp("fixture op", false, time.Second, func(context.Context) (Result, error) {
		return Result{Message: "fixture result"}, nil
	})
	waitWork(t, u)
	u.refreshLog()
	text := u.logView.GetText(false)
	if !strings.Contains(text, "tui: fixture op: started") || !strings.Contains(text, "tui: fixture op: done") {
		t.Fatalf("operation not logged in the panel: %q", text)
	}

	press(u, tcell.KeyRune, 'l')
	if !u.logMax || u.root.GetItemCount() != 2 {
		t.Fatal("l must show the log full screen")
	}
	press(u, tcell.KeyEscape, 0)
	if u.logMax {
		t.Fatal("Esc must leave the full-screen log")
	}

	u.setLogLevel(LogOff)
	if log.Default() != nil || !strings.Contains(u.status.GetText(false), "LOG: OFF") {
		t.Fatal("log not turned off")
	}
	for _, sz := range [][2]int{{110, 32}, {60, 24}} {
		s.SetSize(sz[0], sz[1])
		u.layout(sz[0])
		u.pages.SetRect(0, 0, sz[0], sz[1])
		u.pages.Draw(s)
	}
}

func TestPairCodeIsShownAsTyped(t *testing.T) {
	u, s := newTestUI(t)
	u.pairForm()
	_, front := u.pages.GetFrontPage()
	form := front.(*tview.Flex).GetItem(1).(*tview.Form)
	form.GetFormItem(0).(*tview.InputField).SetText(fixtureCode)
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
	if !strings.Contains(screen.String(), fixtureCode) {
		t.Fatal("the pairing code must not be masked")
	}
}

func TestConfirmPutsActionFirstAndFocusesCancel(t *testing.T) {
	u, _ := newTestUI(t)
	ran := false
	u.confirm("fixture", func() { ran = true })
	press(u, tcell.KeyEnter, 0)
	if ran || u.dialog {
		t.Fatal("Enter must choose Cancel")
	}
	u.confirm("fixture", func() { ran = true })
	press(u, tcell.KeyBacktab, 0)
	press(u, tcell.KeyEnter, 0)
	if !ran {
		t.Fatal("Confirm must be the first button")
	}
}
