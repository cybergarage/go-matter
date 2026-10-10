// Copyright (C) 2026 The go-matter Authors. Licensed under the Apache License, Version 2.0.

package tui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter/protocol/im"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"github.com/spf13/cobra"
)

// Command returns the standalone TUI subcommand without starting a commissioner.
func Command() *cobra.Command {
	var live bool
	var dir string
	command := &cobra.Command{Use: "tui", Short: "Full-screen controller (offline fixture by default)", SilenceUsage: true,
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error { log.SetDefault(nil); return nil }, Args: cobra.NoArgs, RunE: func(_ *cobra.Command, _ []string) error {
			// Disable library logging globally before any code/PIN can reach transports.
			log.SetDefault(nil)
			var backend Backend = &Demo{}
			mode := "OFFLINE FIXTURE — fictional devices / no network"
			if live {
				if dir == "" {
					home, err := os.UserHomeDir()
					if err != nil {
						return errors.New("cannot resolve store location")
					}
					dir = filepath.Join(home, ".matterctl")
				}
				b, err := openLiveDirectory(dir)
				if err != nil {
					return err
				}
				backend = b
				mode = "LIVE — saved devices / network only after confirmation"
			}
			screen, err := tcell.NewScreen()
			if err != nil {
				return errors.New("a supported terminal is required")
			}
			managed := &managedScreen{Screen: screen}
			if err := managed.Init(); err != nil {
				managed.Fini()
				return errors.New("cannot initialize terminal")
			}
			defer managed.Fini()
			return NewUI(backend, mode, managed).Run()
		}}
	command.Flags().BoolVar(&live, "live", false, "enable real operations after UI confirmation (never used in tests)")
	command.Flags().StringVar(&dir, "store-dir", "", "commissioner store (default ~/.matterctl); explicit initialization; one process only")
	return command
}

// tview.SetScreen ignores Init errors. Initialize explicitly, and make lifecycle
// calls idempotent so both tview shutdown and command cleanup restore safely.
type managedScreen struct {
	tcell.Screen
	initOnce, finiOnce sync.Once
	initErr            error
}

func (s *managedScreen) Init() error {
	s.initOnce.Do(func() { s.initErr = s.Screen.Init() })
	return s.initErr
}
func (s *managedScreen) Fini() {
	// tcell Fini is only valid after successful Init (its quit channel may be nil).
	if s.initErr == nil {
		s.finiOnce.Do(s.Screen.Fini)
	}
}

type completion struct {
	result     Result
	err        error
	inventory  bool
	generation uint64
	node       uint64
}
type UI struct {
	app                          *tview.Application
	screen                       tcell.Screen
	backend                      Backend
	pages                        *tview.Pages
	devices, paths, actions      *tview.List
	detail                       *tview.TextView
	search                       *tview.InputField
	status                       *tview.TextView
	body                         *tview.Flex
	records                      []Device
	visible                      []Device
	inventory                    []Path
	focus                        int
	dialog                       bool
	busy                         bool
	rootCtx                      context.Context
	rootCancel                   context.CancelFunc
	cancel                       context.CancelFunc
	results                      chan completion
	workDone                     chan struct{}
	selectedDevice, selectedPath int
	generation                   uint64
	mode                         string
}

func NewUI(backend Backend, mode string, screen tcell.Screen) *UI {
	ctx, cancel := context.WithCancel(context.Background())
	u := &UI{app: tview.NewApplication().SetScreen(screen), screen: screen, backend: backend, rootCtx: ctx, rootCancel: cancel, results: make(chan completion, 1), mode: mode}
	u.devices = tview.NewList().ShowSecondaryText(false)
	u.devices.SetBorder(true).SetTitle(" Saved devices ")
	u.paths = tview.NewList().ShowSecondaryText(false)
	u.paths.SetBorder(true).SetTitle(" Endpoints / clusters / attributes ")
	u.actions = tview.NewList().ShowSecondaryText(false)
	u.actions.SetBorder(true).SetTitle(" Menu ")
	u.detail = tview.NewTextView().SetWrap(true)
	u.detail.SetBorder(true).SetTitle(" Result / last observation ")
	u.detail.SetText("Saved does not mean connected. Select Reconnect / inspect.\nOnly supported operations appear. Values are snapshots, not subscriptions.")
	u.status = tview.NewTextView().SetText(mode + "\nTab / arrows / Enter | / search | ? help | Esc cancel | q / Ctrl-C quit")
	u.search = tview.NewInputField().SetLabel("Search: ").SetChangedFunc(func(s string) { u.filter(s) }).SetDoneFunc(func(_ tcell.Key) { u.setFocus(0) })
	u.body = tview.NewFlex()
	root := tview.NewFlex().SetDirection(tview.FlexRow).AddItem(u.status, 3, 0, false).AddItem(u.search, 1, 0, false).AddItem(u.body, 0, 1, true)
	u.pages = tview.NewPages().AddPage("main", root, true, true)
	u.devices.SetChangedFunc(func(index int, _ string, _ string, _ rune) {
		u.selectedDevice = index
		u.clearSelection()
		u.detail.SetText("Saved / unverified node selected. Reconnect / inspect to query it.\nNo ongoing connection or subscription.")
		u.updateActions()
	}).SetSelectedFunc(func(_ int, _ string, _ string, _ rune) { u.setFocus(2) })
	u.paths.SetChangedFunc(func(index int, _ string, _ string, _ rune) {
		u.selectedPath = index
		u.generation++
		if u.cancel != nil {
			u.cancel()
		}
		if p, ok := u.path(); ok {
			u.detail.SetText(pathDetail(p))
		}
		u.updateActions()
	}).SetSelectedFunc(func(_ int, _ string, _ string, _ rune) { u.setFocus(2) })
	u.app.SetRoot(u.pages, true).EnableMouse(false).SetInputCapture(u.key)
	u.app.SetBeforeDrawFunc(func(s tcell.Screen) bool { u.drain(); w, _ := s.Size(); u.layout(w); return false })
	u.reload()
	if f, ok := backend.(fabricBackend); ok {
		summary, err := f.Overview()
		if err != nil {
			u.detail.SetText(err.Error())
		} else {
			u.detail.SetText(summary.String())
		}
	}
	u.updateActions()
	u.setFocus(0)
	return u
}
func (u *UI) Run() error {
	err := u.app.Run()
	u.rootCancel()
	if u.cancel != nil {
		u.cancel()
	}
	if u.workDone != nil {
		select {
		case <-u.workDone:
		case <-time.After(5 * time.Second):
			return errors.New("terminal restored; operation shutdown did not finish within 5s. Pairing outcome may be uncertain")
		}
	}
	return errors.Join(err, u.backend.Close())
}
func (u *UI) layout(width int) {
	u.body.Clear()
	if width < 95 {
		u.body.SetDirection(tview.FlexRow).AddItem(u.devices, 0, 1, false).AddItem(u.paths, 0, 1, false).AddItem(u.actions, 0, 1, false).AddItem(u.detail, 0, 1, false)
	} else {
		left := tview.NewFlex().SetDirection(tview.FlexRow).AddItem(u.devices, 0, 1, false).AddItem(u.actions, 0, 1, false)
		right := tview.NewFlex().SetDirection(tview.FlexRow).AddItem(u.paths, 0, 1, false).AddItem(u.detail, 0, 1, false)
		u.body.SetDirection(tview.FlexColumn).AddItem(left, 36, 0, false).AddItem(right, 0, 1, false)
	}
}
func (u *UI) reload() {
	u.clearSelection()
	u.records = nil
	u.visible = nil
	u.devices.Clear()
	records, err := u.backend.List()
	if err != nil {
		u.detail.SetText("ERROR loading saved devices; inventory and values cleared.")
		u.updateActions()
		return
	}
	u.records = records
	u.filter(u.search.GetText())
}
func (u *UI) filter(s string) {
	var selected uint64
	if d, ok := u.device(); ok {
		selected = d.ID
	}
	u.clearSelection()
	u.devices.Clear()
	u.visible = nil
	for _, d := range u.records {
		if strings.Contains(strings.ToLower(d.Name+fmt.Sprintf(" %016X", d.ID)), strings.ToLower(s)) {
			u.visible = append(u.visible, d)
			u.devices.AddItem("[saved / unverified] "+d.Name, "", 0, nil)
		}
	}
	for i, d := range u.visible {
		if d.ID == selected {
			u.devices.SetCurrentItem(i)
		}
	}
	u.updateActions()
}
func (u *UI) clearSelection() {
	u.generation++
	if u.cancel != nil {
		u.cancel()
	}
	u.inventory = nil
	u.selectedPath = -1
	u.paths.Clear()
	u.detail.SetText("Value: NOT FETCHED. Inventory unknown; inspect the selected node.")
}
func (u *UI) device() (Device, bool) {
	i := u.selectedDevice
	if i < 0 || i >= len(u.visible) {
		return Device{}, false
	}
	return u.visible[i], true
}
func (u *UI) path() (Path, bool) {
	i := u.selectedPath
	if i < 0 || i >= len(u.inventory) {
		return Path{}, false
	}
	return u.inventory[i], true
}
func (u *UI) updateActions() {
	u.actions.Clear()
	u.actions.AddItem("Reload saved devices", "", 0, func() {
		if !u.busy {
			u.reload()
		}
	})
	if f, ok := u.backend.(fabricBackend); ok {
		u.actions.AddItem("Fabric overview", "", 0, func() {
			summary, err := f.Overview()
			if err != nil {
				u.detail.SetText(err.Error())
			} else {
				u.detail.SetText(summary.String())
			}
		})
		summary, err := f.Overview()
		if err == nil && !summary.Present {
			u.actions.AddItem("Create new fabric", "", 0, u.fabricForm)
		}
		if err == nil && summary.Valid {
			u.actions.AddItem("Pair device (manual / QR)", "", 0, u.pairForm)
		}
	} else {
		u.actions.AddItem("Pair device (manual / QR)", "", 0, u.pairForm)
	}
	if d, ok := u.device(); ok {
		u.actions.AddItem("Reconnect / inspect", "", 0, func() {
			u.confirm("Connect to selected node and read Descriptor inventory?", func() {
				u.start(true, 30*time.Second, func(ctx context.Context) (Result, error) { return u.backend.Inspect(ctx, d.ID) })
			})
		})
		if p, ok := u.path(); ok {
			if readable(p) {
				u.actions.AddItem("Read selected attribute", "", 0, func() {
					u.confirm("Read selected node: "+p.String()+"?", func() {
						u.start(false, 30*time.Second, func(ctx context.Context) (Result, error) { return u.backend.Read(ctx, d.ID, p) })
					})
				})
			}
			for _, c := range p.Commands {
				name := map[im.CommandID]string{0: "Off", 1: "On", 2: "Toggle"}[c]
				if name == "" {
					continue
				}
				u.actions.AddItem("Invoke "+name+" + fresh readback", "", 0, func() {
					u.confirm("Send "+name+" to "+d.Name+" / "+p.String()+"?", func() {
						u.start(false, 30*time.Second, func(ctx context.Context) (Result, error) { return u.backend.Invoke(ctx, d.ID, p, c) })
					})
				})
			}
		}
	}
}
func (u *UI) setFocus(i int) {
	u.focus = (i + 4) % 4
	items := []tview.Primitive{u.devices, u.paths, u.actions, u.detail}
	u.app.SetFocus(items[u.focus])
	for j, l := range []*tview.List{u.devices, u.paths, u.actions} {
		color := tcell.ColorGray
		if j == u.focus {
			color = tcell.ColorAqua
		}
		l.SetBorderColor(color)
	}
}
func (u *UI) closeDialog() { u.pages.RemovePage("dialog"); u.dialog = false; u.setFocus(u.focus) }
func (u *UI) confirm(text string, fn func()) {
	if u.busy {
		u.detail.SetText("Operation in progress. Esc requests cancellation; wait for completion.")
		return
	}
	generation := u.generation
	modal := tview.NewModal().SetText(text).AddButtons([]string{"Cancel", "Confirm"}).SetDoneFunc(func(i int, _ string) {
		u.closeDialog()
		if i == 1 && generation == u.generation {
			fn()
		}
	})
	u.dialog = true
	u.pages.AddPage("dialog", modal, true, true)
	u.app.SetFocus(modal)
}
func (u *UI) pairForm() {
	if u.busy {
		return
	}
	field := tview.NewInputField().SetLabel("Code / MT: ").SetMaskCharacter('*').SetFieldWidth(30)
	note := tview.NewTextView().SetText("Manual 11/21 digits or MT: QR text. Input is masked.\nExisting fabric required in LIVE mode; no Wi-Fi provisioning.\nPairing changes persistent device access. Cancel may leave an uncertain outcome.")
	form := tview.NewForm().AddFormItem(field)
	form.AddButton("Cancel", func() { field.SetText(""); u.closeDialog() }).AddButton("Validate", func() {
		p, err := ParsePayload(field.GetText())
		if err != nil {
			note.SetText(err.Error())
			return
		}
		field.SetText("")
		u.closeDialog()
		u.confirm("Valid standard onboarding payload. Commission into this controller's fabric?\nDo not repeat after an uncertain outcome. No credential is shown.", func() {
			u.start(false, 120*time.Second, func(ctx context.Context) (Result, error) { return u.backend.Pair(ctx, p) })
		})
	})
	form.SetFocus(1)
	box := tview.NewFlex().SetDirection(tview.FlexRow).AddItem(note, 5, 0, false).AddItem(form, 0, 1, true)
	box.SetBorder(true).SetTitle(" Pair device ")
	// Flex auto-resizes forms with the terminal and preserves widget state.
	u.dialog = true
	u.pages.AddPage("dialog", box, true, true)
	u.app.SetFocus(form)
}
func (u *UI) start(inventory bool, timeout time.Duration, fn func(context.Context) (Result, error)) {
	if u.busy {
		return
	}
	u.busy = true
	if inventory {
		u.clearSelection()
	}
	generation := u.generation
	var node uint64
	if d, ok := u.device(); ok {
		node = d.ID
	}
	ctx, cancel := context.WithTimeout(u.rootCtx, timeout)
	u.cancel = cancel
	u.workDone = make(chan struct{})
	done := u.workDone
	u.detail.SetText("WORKING: operation in progress (no per-stage API).\nEsc requests cancellation. No automatic retries.\nPairing may have changed device state before cancellation.")
	go func() {
		defer close(done)
		defer cancel()
		r, e := fn(ctx)
		select {
		case u.results <- completion{result: r, err: e, inventory: inventory, generation: generation, node: node}:
		case <-u.rootCtx.Done():
			return
		}
		_ = u.screen.PostEvent(tcell.NewEventResize(0, 0))
	}()
}
func (u *UI) drain() {
	select {
	case c := <-u.results:
		u.busy = false
		u.cancel = nil
		d, selected := u.device()
		if c.generation != u.generation || (c.node != 0 && (!selected || d.ID != c.node)) {
			return
		}
		if c.err != nil {
			if errors.Is(c.err, context.Canceled) || errors.Is(c.err, context.DeadlineExceeded) {
				u.detail.SetText("CANCELED / TIMEOUT: outcome may be uncertain. Read or reload before retrying.")
			} else {
				u.detail.SetText(c.err.Error())
			}
			return
		}
		if c.node == 0 {
			u.reload()
		}
		u.updateActions()
		u.detail.SetText(c.result.Message)
		if c.inventory {
			u.inventory = c.result.Paths
			u.paths.Clear()
			for _, p := range u.inventory {
				u.paths.AddItem(p.String(), "", 0, nil)
			}
			u.updateActions()
		}
	default:
	}
}
func (u *UI) quit() {
	u.rootCancel()
	if u.cancel != nil {
		u.cancel()
	}
	u.app.Stop()
}
func (u *UI) key(e *tcell.EventKey) *tcell.EventKey {
	if e.Key() == tcell.KeyCtrlC {
		u.quit()
		return nil
	}
	if e.Key() == tcell.KeyEscape {
		switch {
		case u.busy && u.cancel != nil:
			u.cancel()
			u.detail.SetText("Cancellation requested; awaiting transport shutdown. Outcome may be uncertain.")
		case u.dialog:
			u.closeDialog()
		default:
			u.search.SetText("")
			u.setFocus(0)
		}
		return nil
	}
	if e.Rune() == 'q' {
		if _, editing := u.app.GetFocus().(*tview.InputField); !editing {
			u.quit()
			return nil
		}
	}
	if u.busy {
		return nil
	}
	if u.dialog || u.app.GetFocus() == u.search {
		return e
	}
	switch e.Key() {
	case tcell.KeyTab:
		u.setFocus(u.focus + 1)
		return nil
	case tcell.KeyBacktab:
		u.setFocus(u.focus - 1)
		return nil
	}
	switch e.Rune() {
	case 'q':
		u.quit()
		return nil
	case '/':
		u.app.SetFocus(u.search)
		return nil
	case '?':
		u.confirm("Tab/Shift-Tab: panels\nArrows/Enter: select / open menu\n/: search saved nodes\nEsc: cancel form or request operation cancellation\nq/Ctrl-C: cancel work and restore terminal\nResize: layout adapts; 60x24 minimum, 100x30 recommended\nSaved records and last values do not imply a live connection.", func() {})
		return nil
	}
	return e
}

func (u *UI) fabricForm() {
	if u.busy {
		return
	}
	backend, ok := u.backend.(fabricBackend)
	if !ok {
		return
	}
	field := tview.NewInputField().SetLabel("Admin vendor ID: ").SetFieldWidth(12)
	note := tview.NewTextView().SetText("Create a local controller identity; no network operation.\nIDs are automatic. Existing identity is never replaced.\nEnter your assigned vendor ID; 0xFFF1–0xFFF4 are development test IDs.\nKeys/IPK are stored locally, never displayed. Keep the store private.")
	form := tview.NewForm().AddFormItem(field)
	form.AddButton("Cancel", u.closeDialog).AddButton("Validate", func() {
		vendor, err := parseVendor(field.GetText())
		if err != nil {
			note.SetText(err.Error())
			return
		}
		u.closeDialog()
		u.confirm("Generate and save a NEW local fabric identity?\nNo existing identity will be overwritten. No device is registered.\nThe store contains private keys in plaintext (0600 files).", func() {
			u.start(false, 30*time.Second, func(ctx context.Context) (Result, error) { return backend.CreateFabric(ctx, vendor) })
		})
	})
	form.SetFocus(1)
	box := tview.NewFlex().SetDirection(tview.FlexRow).AddItem(note, 6, 0, false).AddItem(form, 0, 1, true)
	box.SetBorder(true).SetTitle(" Create local fabric ")
	u.dialog = true
	u.pages.AddPage("dialog", box, true, true)
	u.app.SetFocus(form)
}
