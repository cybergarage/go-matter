// Copyright (C) 2026 The go-matter Authors. Licensed under the Apache License, Version 2.0.

package tui

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cybergarage/go-matter/matter"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	"github.com/cybergarage/go-matter/matter/protocol/im"
	"github.com/cybergarage/go-matter/matter/store"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// This is a public encoding-test fixture, never an actual appliance credential.
const fixtureCode = "3035-750-7966"

func TestPayloadValidation(t *testing.T) {
	for _, s := range []string{fixtureCode, "MT:Y.ET0EDB00SWDX0IA00"} {
		if _, err := ParsePayload(s); err != nil {
			t.Fatal("public fixture failed validation")
		}
	}
	for _, s := range []string{"", "x" + fixtureCode, "3035-750-7967", "MT:secret", "１２３４５６７８９０１"} {
		if _, err := ParsePayload(s); err == nil {
			t.Fatal("invalid payload accepted")
		} else if strings.Contains(err.Error(), s) && s != "" {
			t.Fatal("input disclosed in error")
		}
	}
}
func newTestUI(t *testing.T) (*UI, tcell.SimulationScreen) {
	t.Helper()
	s := tcell.NewSimulationScreen("UTF-8")
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	u := NewUI(&Demo{}, "OFFLINE FIXTURE — fictional devices / no network", s)
	s.SetSize(110, 32)
	t.Cleanup(func() { u.rootCancel(); s.Fini() })
	return u, s
}
func press(u *UI, key tcell.Key, r rune) {
	e := u.key(tcell.NewEventKey(key, r, tcell.ModNone))
	if e != nil {
		if h := u.app.GetFocus().InputHandler(); h != nil {
			h(e, func(p tview.Primitive) { u.app.SetFocus(p) })
		}
	}
}
func waitWork(t *testing.T, u *UI) {
	t.Helper()
	select {
	case <-u.workDone:
	case <-time.After(time.Second):
		t.Fatal("worker did not finish")
	}
	u.drain()
}
func TestKeysFormsSearchAndResize(t *testing.T) {
	u, s := newTestUI(t)
	press(u, tcell.KeyTab, 0)
	if u.app.GetFocus() != u.paths {
		t.Fatal("Tab focus")
	}
	press(u, tcell.KeyBacktab, 0)
	if u.app.GetFocus() != u.devices {
		t.Fatal("Shift-Tab focus")
	}
	press(u, tcell.KeyRune, '/')
	u.search.SetText("no match")
	if len(u.visible) != 0 {
		t.Fatal("search")
	}
	press(u, tcell.KeyEscape, 0)
	if len(u.visible) != 1 {
		t.Fatal("escape search")
	}
	u.pairForm()
	press(u, tcell.KeyEscape, 0)
	if u.dialog {
		t.Fatal("form cancel")
	}
	u.pairForm()
	// The form is kept as a child; test input masking and validation without logging it.
	_, front := u.pages.GetFrontPage()
	form := front.(*tview.Flex).GetItem(1).(*tview.Form)
	field := form.GetFormItem(0).(*tview.InputField)
	field.SetText("invalid")
	form.SetFocus(2)
	u.app.SetFocus(form)
	press(u, tcell.KeyEnter, 0)
	if !u.dialog || u.busy {
		t.Fatal("invalid form mutated state")
	}
	field.SetText(fixtureCode)
	press(u, tcell.KeyEnter, 0)
	if !u.dialog || u.busy {
		t.Fatal("pair confirmation missing")
	}
	if field.GetText() != "" {
		t.Fatal("code retained after validation")
	}
	press(u, tcell.KeyEnter, 0)
	if u.busy {
		t.Fatal("Cancel must be first confirmation button")
	}
	press(u, tcell.KeyRune, '?')
	if !u.dialog {
		t.Fatal("help")
	}
	press(u, tcell.KeyEscape, 0)
	for _, sz := range [][2]int{{110, 32}, {60, 24}, {35, 15}} {
		s.SetSize(sz[0], sz[1])
		u.layout(sz[0])
		u.pages.SetRect(0, 0, sz[0], sz[1])
		u.pages.Draw(s)
	}
}
func TestAsyncCancelAndReadback(t *testing.T) {
	u, _ := newTestUI(t)
	u.start(false, time.Second, func(ctx context.Context) (Result, error) { <-ctx.Done(); return Result{}, ctx.Err() })
	press(u, tcell.KeyEscape, 0)
	waitWork(t, u)
	if u.busy || !strings.Contains(u.detail.GetText(false), "CANCELED") {
		t.Fatal("cancel completion")
	}
	u.start(true, time.Second, func(ctx context.Context) (Result, error) { return u.backend.Inspect(ctx, 0x101) })
	waitWork(t, u)
	if len(u.inventory) != 2 {
		t.Fatal("inventory")
	}
	p := u.inventory[0]
	u.start(false, time.Second, func(ctx context.Context) (Result, error) { return u.backend.Invoke(ctx, 0x101, p, 1) })
	waitWork(t, u)
	text := u.detail.GetText(false)
	if !strings.Contains(text, "INVOKE ACKNOWLEDGED") || !strings.Contains(text, "FRESH READ") {
		t.Fatal("readback not distinguished")
	}
}
func TestRunRestoresScreenAndCancels(t *testing.T) {
	s := tcell.NewSimulationScreen("UTF-8")
	u := NewUI(&Demo{}, "OFFLINE FIXTURE", s)
	ready := make(chan struct{}, 1)
	u.app.SetAfterDrawFunc(func(_ tcell.Screen) {
		select {
		case ready <- struct{}{}:
		default:
		}
	})
	done := make(chan error, 1)
	go func() { done <- u.Run() }()
	select {
	case <-ready:
	case <-time.After(3 * time.Second):
		t.Fatal("app did not draw")
	}
	s.InjectKey(tcell.KeyCtrlC, 0, tcell.ModNone)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("quit failed")
	}
	w, h := s.Size()
	if w != 0 || h != 0 {
		t.Fatal("simulation screen was not finalized")
	}
	if u.rootCtx.Err() != context.Canceled {
		t.Fatal("root not canceled")
	}
}

type fakeNode struct {
	matter.Node
	invoked bool
	readErr bool
}

func (n *fakeNode) Invoke(_ im.EndpointID, _ im.ClusterID, _ im.CommandID, _ []byte) (*im.InvokeResponse, error) {
	n.invoked = true
	return &im.InvokeResponse{}, nil
}
func (n *fakeNode) ReadAttribute(_ im.EndpointID, _ im.ClusterID, _ im.AttributeID) (*im.ReadResponse, error) {
	if n.readErr {
		return nil, errors.New("fixture")
	}
	enc := tlv.NewEncoder()
	enc.PutBool(tlv.NewAnonymousTag(), true)
	dec := tlv.NewDecoderWithBytes(enc.Bytes())
	dec.Next()
	return &im.ReadResponse{Value: dec.Element()}, nil
}
func TestInvokeRequiresAdvertisedCommandAndFreshRead(t *testing.T) {
	p := Path{Endpoint: 1, Cluster: 6, Attribute: 0}
	n := &fakeNode{}
	if _, err := invokeNode(n, p, 1); err == nil || n.invoked {
		t.Fatal("unadvertised command sent")
	}
	p.Commands = []im.CommandID{1}
	r, err := invokeNode(n, p, 1)
	if err != nil || !strings.Contains(r.Message, "FRESH READ") {
		t.Fatal("fresh read missing")
	}
	n.readErr = true
	r, err = invokeNode(n, p, 1)
	if err != nil || !strings.Contains(r.Message, "readback FAILED") {
		t.Fatal("ack reported as readback")
	}
}

type fakeCommissioner struct {
	matter.Commissioner
	st     store.Store
	fail   bool
	starts int
}

func (c *fakeCommissioner) Start() error { c.starts++; return nil }
func (*fakeCommissioner) Stop() error    { return nil }
func (c *fakeCommissioner) Commission(_ context.Context, _ matter.OnboardingPayload, _ ...matter.CommissionOption) (matter.Commissionee, error) {
	if c.fail {
		return nil, errors.New("fixture failure")
	}
	_ = c.st.SaveFabric(store.FabricRecord{FabricID: 1})
	_ = c.st.SaveCommissionee(store.CommissioneeRecord{NodeID: 42, FabricID: 1, CompressedFabricID: 1})
	return fakeCommissionee{}, nil
}

type fakeCommissionee struct{ matter.Commissionee }

func (fakeCommissionee) NodeID() (matter.NodeID, bool) { return 42, true }

type failStore struct{ store.Store }

func (failStore) SaveCommissionee(store.CommissioneeRecord) error {
	return errors.New("synthetic save error")
}
func seedStore(t *testing.T, st store.Store) {
	t.Helper()
	if err := st.SaveFabric(store.FabricRecord{FabricID: 1, RootPrivateKey: []byte("fictional"), PrivateKey: []byte("fictional"), RootCertificate: []byte("fictional"), NOC: []byte("fictional"), IPK: make([]byte, 16)}); err != nil {
		t.Fatal(err)
	}
}
func TestPairPersistenceFailureAndReload(t *testing.T) {
	st, err := store.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	seedStore(t, st)
	b := NewLive(st)
	f := &fakeCommissioner{st: b.st}
	b.cmr = f
	p, _ := ParsePayload(fixtureCode)
	r, err := b.Pair(context.Background(), p)
	if err != nil || !strings.Contains(r.Message, "SAVED") {
		t.Fatal("pair save verification failed")
	}
	ds, err := NewLive(st).List()
	if err != nil || len(ds) != 1 || ds[0].ID != 42 {
		t.Fatal("restart list")
	}
	// Re-saving one identity must replace the record rather than append duplicates.
	if err := st.SaveCommissionee(store.CommissioneeRecord{NodeID: 42, CompressedFabricID: 1}); err != nil {
		t.Fatal(err)
	}
	ds, _ = b.List()
	if len(ds) != 1 {
		t.Fatal("duplicate record")
	}
	seedStore(t, st)
	b = NewLive(failStore{Store: st})
	b.cmr = &fakeCommissioner{st: b.st}
	r, err = b.Pair(context.Background(), p)
	if err != nil || !strings.Contains(r.Message, "LOCAL SAVE FAILED") {
		t.Fatal("save failure hidden")
	}
	b = NewLive(store.NewMemStore())
	f = &fakeCommissioner{st: b.st}
	b.cmr = f
	if _, err = b.Pair(context.Background(), p); err == nil || f.starts != 0 {
		t.Fatal("empty fabric started transport")
	}
}

type screenCell struct {
	X, Y                   int
	Rune                   string
	Foreground, Background string
}

func screenshot(t *testing.T, u *UI, s tcell.SimulationScreen, name string) {
	t.Helper()
	dir := os.Getenv("TUI_SCREENSHOT_DIR")
	if dir == "" {
		return
	}
	w, h := s.Size()
	u.layout(w)
	u.pages.SetRect(0, 0, w, h)
	u.pages.Draw(s)
	s.Show()
	var cells []screenCell
	for y := range h {
		for x := range w {
			r, _, style, _ := s.GetContent(x, y)
			fg, bg, _ := style.Decompose()
			cells = append(cells, screenCell{X: x, Y: y, Rune: string(r), Foreground: fmtColor(fg), Background: fmtColor(bg)})
		}
	}
	data, err := json.Marshal(struct {
		Width, Height int
		Cells         []screenCell
	}{w, h, cells})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, name+".json"), data, 0644); err != nil {
		t.Fatal(err)
	}
}
func fmtColor(c tcell.Color) string {
	if c == tcell.ColorDefault {
		return "#101820"
	}
	return c.CSS()
}
func TestFictionalScreenshots(t *testing.T) {
	u, s := newTestUI(t)
	r, _ := u.backend.Inspect(context.Background(), 0x101)
	u.inventory = r.Paths
	for _, p := range r.Paths {
		u.paths.AddItem(p.String(), "", 0, nil)
	}
	u.updateActions()
	if u.actions.GetItemCount() < 7 {
		t.Fatalf("missing fixture read/invoke menus: device=%v paths=%d menu=%d", u.visible, len(u.inventory), u.actions.GetItemCount())
	}
	u.detail.SetText("OFFLINE FIXTURE / INVOKE ACKNOWLEDGED\nOFFLINE FIXTURE / FRESH READ: EP 1 / cluster 0x0006 / attr 0x0000 = true\nNo actual device, credential or network.")
	screenshot(t, u, s, "tui")
	u.pairForm()
	screenshot(t, u, s, "tui-pair")
	press(u, tcell.KeyEscape, 0)
	s.SetSize(60, 24)
	screenshot(t, u, s, "tui-compact")
}

type blockingNode struct {
	matter.Node
	closed chan struct{}
	once   sync.Once
}

func (n *blockingNode) Close() error { n.once.Do(func() { close(n.closed) }); return nil }
func (n *blockingNode) ReadAttribute(_ im.EndpointID, _ im.ClusterID, _ im.AttributeID) (*im.ReadResponse, error) {
	<-n.closed
	return nil, errors.New("synthetic closed transport")
}

type connectFixture struct {
	matter.Commissioner
	node  matter.Node
	calls int
}

func (*connectFixture) Start() error { return nil }
func (*connectFixture) Stop() error  { return nil }
func (c *connectFixture) Connect(_ context.Context, _ uint64) (matter.Node, error) {
	c.calls++
	return c.node, nil
}
func TestLiveReadDeadlineClosesTransport(t *testing.T) {
	n := &blockingNode{closed: make(chan struct{})}
	c := &connectFixture{node: n}
	b := NewLive(store.NewMemStore())
	b.cmr = c
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := b.Read(ctx, 42, Path{Endpoint: 1, Cluster: 6, Attribute: 0})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("IM read deadline did not close transport")
	}
	if c.calls != 1 {
		t.Fatal("unexpected automatic reconnect")
	}
	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	_, err = b.Read(ctx, 42, Path{Cluster: 6})
	if !errors.Is(err, context.Canceled) || c.calls != 1 {
		t.Fatal("canceled read opened a session")
	}
}
func TestFailedPairPreservesExistingRecords(t *testing.T) {
	st := store.NewMemStore()
	seedStore(t, st)
	if err := st.SaveCommissionee(store.CommissioneeRecord{NodeID: 7, CompressedFabricID: 1}); err != nil {
		t.Fatal(err)
	}
	b := NewLive(st)
	b.cmr = &fakeCommissioner{st: b.st, fail: true}
	p, _ := ParsePayload(fixtureCode)
	if _, err := b.Pair(context.Background(), p); err == nil {
		t.Fatal("failure hidden")
	}
	ds, _ := b.List()
	if len(ds) != 1 || ds[0].ID != 7 {
		t.Fatal("old records changed after failure")
	}
}
func TestFixturePairRequiresConfirmationAndRejectsDuplicate(t *testing.T) {
	u, _ := newTestUI(t)
	p, _ := ParsePayload(fixtureCode)
	u.confirm("Fixture pair", func() {
		u.start(false, time.Second, func(ctx context.Context) (Result, error) { return u.backend.Pair(ctx, p) })
	})
	// Move to Confirm, then Enter: no command-line string is involved.
	press(u, tcell.KeyTab, 0)
	press(u, tcell.KeyEnter, 0)
	if !u.busy {
		t.Fatal("confirmed pair did not run")
	}
	waitWork(t, u)
	u.reload()
	if len(u.records) != 2 {
		t.Fatal("fixture success missing from menu")
	}
	u.start(false, time.Second, func(ctx context.Context) (Result, error) { return u.backend.Pair(ctx, p) })
	waitWork(t, u)
	if !strings.Contains(u.detail.GetText(false), "duplicate") {
		t.Fatal("duplicate fixture accepted")
	}
}

func TestAmbiguousNodeIDsAreNotSelectable(t *testing.T) {
	st := store.NewMemStore()
	for _, fabric := range []uint64{1, 2} {
		if err := st.SaveCommissionee(store.CommissioneeRecord{NodeID: 42, CompressedFabricID: fabric}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := NewLive(st).List(); err == nil {
		t.Fatal("ambiguous stored identities were selectable")
	}
}

type failedScreen struct {
	tcell.Screen
	initCalls, finiCalls int
}

func (s *failedScreen) Init() error { s.initCalls++; return errors.New("synthetic terminal failure") }
func (s *failedScreen) Fini()       { s.finiCalls++ }
func TestTerminalInitializationAndCleanupAreIdempotent(t *testing.T) {
	raw := &failedScreen{}
	screen := &managedScreen{Screen: raw}
	err1, err2 := screen.Init(), screen.Init()
	if err1 == nil || err2 == nil {
		t.Fatal("terminal error hidden")
	}
	screen.Fini()
	screen.Fini()
	if raw.initCalls != 1 || raw.finiCalls != 0 {
		t.Fatal("invalid cleanup after failed initialization")
	}
	sim := tcell.NewSimulationScreen("UTF-8")
	successful := &managedScreen{Screen: sim}
	if err := successful.Init(); err != nil {
		t.Fatal(err)
	}
	successful.Fini()
	successful.Fini()
}
