// Copyright (C) 2026 The go-matter Authors. Licensed under the Apache License, Version 2.0.

package tui

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cybergarage/go-matter/matter"
	"github.com/cybergarage/go-matter/matter/datamodel"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	"github.com/cybergarage/go-matter/matter/protocol/im"
	"github.com/gdamore/tcell/v2"
)

func startupPath() Path {
	revision := uint16(6)
	features := uint32(1)
	return Path{Endpoint: 1, Cluster: 6, Attribute: 0x4003, ObservedRevision: &revision, ObservedFeatures: &features}
}
func TestDBTypedInputRejectsOutOfRangeEnumAndNull(t *testing.T) {
	s, err := writableSchema(startupPath())
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"Off", "On", "Toggle", "0", "1", "0x02", "null"} {
		if _, err = s.parse(text); err != nil {
			t.Fatalf("enum rejected %q: %v", text, err)
		}
	}
	for _, text := range []string{"3", "255", "-1", "unknown", "true", "1;2"} {
		if _, err = s.parse(text); err == nil {
			t.Fatalf("enum accepted %q", text)
		}
	}
	p := startupPath()
	p.Attribute = 0x4001
	s, err = writableSchema(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"0", "65535", "0xFFFF"} {
		if _, err = s.parse(text); err != nil {
			t.Fatal(err)
		}
	}
	for _, text := range []string{"-1", "65536", "18446744073709551616", "null"} {
		if _, err = s.parse(text); err == nil {
			t.Fatal("invalid unsigned accepted")
		}
	}
	// These primitive forms are implemented and tested, but no additional physical
	// bool/signed attribute is added to the conservative On/Off allowlist.
	a := datamodel.Attribute{Type: "temperature", Writable: true, Nullable: true, Definition: datamodel.Element{Attributes: []datamodel.XMLAttribute{{Name: "min", Value: "-500"}, {Name: "max", Value: "500"}}}}
	s, err = schemaForAttribute(a, 0x402)
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"-500", "500", "0", "null"} {
		if _, err = s.parse(text); err != nil {
			t.Fatal(err)
		}
	}
	for _, text := range []string{"-501", "501", "32768", "false"} {
		if _, err = s.parse(text); err == nil {
			t.Fatal("invalid signed accepted")
		}
	}
	a.Type = "boolean"
	a.Nullable = false
	s, err = schemaForAttribute(a, 6)
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"true", "false"} {
		if _, err = s.parse(text); err != nil {
			t.Fatal(err)
		}
	}
	for _, text := range []string{"1", "null", "TRUE"} {
		if _, err = s.parse(text); err == nil {
			t.Fatal("invalid bool accepted")
		}
	}
}
func TestSETExclusionsAndRequiredObservedContext(t *testing.T) {
	tests := []struct {
		change func(*Path)
		reason string
	}{
		{func(p *Path) { p.Attribute = 0 }, "readonly"},
		{func(p *Path) { p.Cluster = 0x101 }, "door lock"},
		{func(p *Path) { p.ObservedRevision = nil }, "revision"},
		{func(p *Path) { r := uint16(5); p.ObservedRevision = &r }, "revision"},
		{func(p *Path) { p.ObservedFeatures = nil }, "FeatureMap"},
		{func(p *Path) { f := uint32(0); p.ObservedFeatures = &f }, "lighting"},
		{func(p *Path) { f := uint32(5); p.ObservedFeatures = &f }, "OffOnly"},
		{func(p *Path) { f := uint32(8); p.ObservedFeatures = &f }, "unknown feature"},
	}
	for _, test := range tests {
		p := startupPath()
		test.change(&p)
		_, err := writableSchema(p)
		if err == nil || !strings.Contains(err.Error(), test.reason) {
			t.Fatalf("missing exclusion %s: %v", test.reason, err)
		}
	}
	a := datamodel.Attribute{Writable: true, Type: "boolean", Definition: datamodel.Element{Attributes: []datamodel.XMLAttribute{{Name: "mustUseTimedWrite", Value: "true"}}}}
	if _, err := schemaForAttribute(a, 6); err == nil || !strings.Contains(err.Error(), "TimedWrite") {
		t.Fatal("TimedWrite permitted")
	}
	a.Definition = datamodel.Element{}
	a.Type = "DeviceTypeStruct"
	if _, err := schemaForAttribute(a, 0x1D); err == nil {
		t.Fatal("struct permitted")
	}
}

type writingNode struct {
	readStatus uint8
	matter.Node
	writes, reads     int
	status            uint8
	writeErr, readErr bool
	actual            tlv.Element
	cancel            context.CancelFunc
	encoded           tlv.Element
}

func (n *writingNode) WriteAttribute(_ im.EndpointID, _ im.ClusterID, _ im.AttributeID, put func(tlv.Encoder) error) (*im.WriteResponse, error) {
	n.writes++
	enc := tlv.NewEncoder()
	if err := put(enc); err != nil {
		return nil, err
	}
	dec := tlv.NewDecoderWithBytes(enc.Bytes())
	dec.Next()
	n.encoded = dec.Element()
	if n.writeErr {
		return nil, errors.New("fixture timeout")
	}
	if n.cancel != nil {
		n.cancel()
	}
	return &im.WriteResponse{Status: im.InvokeStatus{IMStatus: n.status}}, nil
}
func (n *writingNode) ReadAttribute(_ im.EndpointID, _ im.ClusterID, _ im.AttributeID) (*im.ReadResponse, error) {
	n.reads++
	if n.readErr {
		return nil, errors.New("fixture GET failed")
	}
	if n.readStatus != 0 {
		return &im.ReadResponse{Status: &im.InvokeStatus{IMStatus: n.readStatus}}, nil
	}
	return &im.ReadResponse{Value: n.actual}, nil
}
func TestWriteACKReadbackAndDenialAreDistinct(t *testing.T) {
	p := startupPath()
	s, _ := writableSchema(p)
	value, _ := s.parse("On")
	tests := []struct {
		name  string
		node  writingNode
		want  string
		ack   bool
		err   bool
		reads int
	}{
		{"match", writingNode{actual: scalar(t, func(e tlv.Encoder) { e.PutUnsigned1(tlv.NewAnonymousTag(), 1) })}, "FRESH GET MATCH", true, false, 1},
		{"mismatch", writingNode{actual: scalar(t, func(e tlv.Encoder) { e.PutUnsigned1(tlv.NewAnonymousTag(), 0) })}, "FRESH GET MISMATCH", true, false, 1},
		{"read denied", writingNode{readStatus: uint8(im.StatusUnsupportedAccess)}, "ACCESS DENIED", true, false, 1},
		{"unknown", writingNode{readErr: true}, "Fresh GET UNKNOWN", true, false, 1},
		{"denied", writingNode{status: uint8(im.StatusUnsupportedAccess)}, "WRITE REJECTED / ACCESS DENIED", false, true, 0},
		{"timeout", writingNode{writeErr: true}, "WRITE outcome UNKNOWN", false, true, 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			n := test.node
			r, err := writeNode(context.Background(), &n, p, value)
			message := r.Message
			if err != nil {
				message = err.Error()
			}
			if (err != nil) != test.err || r.Acknowledged != test.ack || !strings.Contains(message, test.want) || n.writes != 1 || n.reads != test.reads {
				t.Fatalf("outcome %s ack=%t writes=%d reads=%d err=%v", message, r.Acknowledged, n.writes, n.reads, err)
			}
			if !value.matches(n.encoded) {
				t.Fatal("encoding changed requested typed value")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	n := &writingNode{cancel: cancel}
	r, err := writeNode(ctx, n, p, value)
	if err != nil || !r.Acknowledged || !strings.Contains(r.Message, "UNKNOWN") || n.reads != 0 || n.writes != 1 {
		t.Fatal("cancellation after ACK lost uncertainty")
	}
	for _, text := range []string{"Off", "Toggle", "null"} {
		v, _ := s.parse(text)
		n = &writingNode{}
		_, _ = writeNode(context.Background(), n, p, v)
		if !v.matches(n.encoded) {
			t.Fatal("enum/null encoding mismatch")
		}
	}
}

type formBackend struct {
	ignoreCancel bool
	Demo
	calls  int
	hold   <-chan struct{}
	result Result
	err    error
}

func (b *formBackend) Set(ctx context.Context, id uint64, p Path, v editValue) (Result, error) {
	b.calls++
	if b.hold != nil {
		<-b.hold
	}
	if ctx.Err() != nil && !b.ignoreCancel {
		return Result{}, ctx.Err()
	}
	if b.err != nil {
		return Result{}, b.err
	}
	if b.result.Message == "" {
		return b.Demo.Set(ctx, id, p, v)
	}
	return b.result, nil
}
func installSETFixture(t *testing.T, u *UI) {
	t.Helper()
	u.inventory = []Path{startupPath()}
	u.paths.Clear()
	u.paths.AddItem(u.inventory[0].String(), "", 0, nil)
	u.updateActions()
}
func TestSETEditorFocusSingleEnterCancellationAndDuplicates(t *testing.T) {
	u, s := newTestUI(t)
	backend := &formBackend{}
	u.backend = backend
	installSETFixture(t, u)
	u.setForm()
	if u.app.GetFocus() != u.editorInput || !u.dialog {
		t.Fatal("input not initially focused")
	}
	u.editorInput.SetText("On")
	screenshot(t, u, s, "tui-set-editor")
	press(u, tcell.KeyEscape, 0)
	s.SetSize(60, 24)
	u.setForm()
	u.editorInput.SetText("On")
	screenshot(t, u, s, "tui-set-editor-compact")
	s.SetSize(110, 32)
	press(u, tcell.KeyEscape, 0)
	if u.dialog || backend.calls != 0 {
		t.Fatal("Esc sent a write")
	}
	u.setForm()
	u.editorInput.SetText("3")
	press(u, tcell.KeyEnter, 0)
	if !u.dialog || u.busy || backend.calls != 0 {
		t.Fatal("invalid input sent")
	}
	u.editorInput.SetText("On")
	press(u, tcell.KeyEnter, 0)
	press(u, tcell.KeyEnter, 0)
	waitWork(t, u)
	if u.dialog || backend.calls != 1 || !strings.Contains(u.detail.GetText(false), "MATCH") {
		t.Fatal("single Enter/duplicate prevention failed")
	}
	screenshot(t, u, s, "tui-set-match")
}
func TestSETStaleEditorAndOldWriteCompletionCannotCrossTargets(t *testing.T) {
	u, _ := newTestUI(t)
	backend := &formBackend{}
	u.backend = backend
	installSETFixture(t, u)
	u.setForm()
	u.editorInput.SetText("On")
	submit := u.editorSubmit
	u.filter("no node")
	submit()
	if backend.calls != 0 || u.busy {
		t.Fatal("stale editor sent write")
	}
	u.filter("")
	installSETFixture(t, u)
	hold := make(chan struct{})
	backend.hold = hold
	backend.ignoreCancel = true
	backend.result = Result{Acknowledged: true, Message: "OLD WRITE ACK"}
	u.setForm()
	u.editorInput.SetText("On")
	press(u, tcell.KeyEnter, 0)
	u.filter("no node")
	close(hold)
	waitWork(t, u)
	if strings.Contains(u.detail.GetText(false), "OLD WRITE") || len(u.inventory) != 0 {
		t.Fatal("late write result applied after selection change")
	}
}
func TestSETEditorTimeoutShowsUnknownWithoutRetry(t *testing.T) {
	u, _ := newTestUI(t)
	calls := 0
	u.start(false, time.Millisecond, func(ctx context.Context) (Result, error) { calls++; <-ctx.Done(); return Result{}, ctx.Err() })
	waitWork(t, u)
	if calls != 1 || !strings.Contains(u.detail.GetText(false), "TIMEOUT") || strings.Contains(u.detail.GetText(false), "MATCH") {
		t.Fatal("timeout retried or claimed success")
	}
}

type changedAdvertisement struct {
	simulatedInventory
	missing  bool
	revision uint64
	features uint64
	fail     bool
}

func (n changedAdvertisement) ids(ep im.EndpointID, cl im.ClusterID, a im.AttributeID) ([]uint32, error) {
	if n.fail {
		return nil, errors.New("fixture denied")
	}
	if n.missing {
		return []uint32{0}, nil
	}
	return n.simulatedInventory.ids(ep, cl, a)
}
func (n changedAdvertisement) scalar(_ im.EndpointID, _ im.ClusterID, a im.AttributeID) (uint64, error) {
	if a == 0xFFFD {
		return n.revision, nil
	}
	return n.features, nil
}
func TestFreshAdvertisementRevisionAndFeatureAreRequired(t *testing.T) {
	p := startupPath()
	for _, n := range []changedAdvertisement{{missing: true, revision: 6, features: 1}, {revision: 5, features: 1}, {revision: 6, features: 0}, {revision: 6, features: 5}, {revision: 6, features: 1, fail: true}} {
		if _, err := refreshSetPath(n, p); err == nil {
			t.Fatal("changed or unavailable advertisement permitted SET")
		}
	}
	if _, err := refreshSetPath(changedAdvertisement{revision: 6, features: 1}, p); err != nil {
		t.Fatal(err)
	}
}

func TestSETDoesNotInterpretUnevaluatedConformance(t *testing.T) {
	original := dictionary
	copyCatalog := *original
	copyCatalog.Clusters = append([]datamodel.Cluster(nil), original.Clusters...)
	for i := range copyCatalog.Clusters {
		if copyCatalog.Clusters[i].ID == 6 {
			copyCatalog.Clusters[i].Attributes = append([]datamodel.Attribute(nil), copyCatalog.Clusters[i].Attributes...)
			for j := range copyCatalog.Clusters[i].Attributes {
				a := &copyCatalog.Clusters[i].Attributes[j]
				if a.ID == 0x4003 {
					a.Definition.Children = []datamodel.Element{{Name: "optionalConform", Children: []datamodel.Element{{Name: "otherwiseConform"}}}}
				}
			}
		}
	}
	dictionary = &copyCatalog
	t.Cleanup(func() { dictionary = original })
	if _, err := writableSchema(startupPath()); err == nil || !strings.Contains(err.Error(), "unevaluated") {
		t.Fatal("unrecognized conformance interpreted")
	}
}
func TestFictionalSettingsAreScopedToExactTarget(t *testing.T) {
	b := &Demo{}
	p := startupPath()
	schema, _ := writableSchema(p)
	value, _ := schema.parse("Toggle")
	if _, err := b.Set(context.Background(), 0x101, p, value); err != nil {
		t.Fatal(err)
	}
	same, _ := b.Read(context.Background(), 0x101, p)
	other, _ := b.Read(context.Background(), 0x102, p)
	if !strings.Contains(same.Message, "Value: 2") || strings.Contains(other.Message, "Value: 2") {
		t.Fatal("fixture configuration crossed node identities")
	}
}

func TestBoolAndSignedScalarEncodingRetainsTypedValues(t *testing.T) {
	for _, test := range []struct {
		typ  string
		text string
	}{{"boolean", "true"}, {"boolean", "false"}, {"int16s", "-32768"}, {"int16s", "32767"}, {"int64s", "-9223372036854775808"}, {"int64u", "18446744073709551615"}} {
		schema, err := schemaForAttribute(datamodel.Attribute{Type: test.typ, Writable: true}, 6)
		if err != nil {
			t.Fatal(err)
		}
		value, err := schema.parse(test.text)
		if err != nil {
			t.Fatal(err)
		}
		enc := tlv.NewEncoder()
		if err = value.encode(enc); err != nil {
			t.Fatal(err)
		}
		dec := tlv.NewDecoderWithBytes(enc.Bytes())
		if !dec.Next() || !value.matches(dec.Element()) {
			t.Fatal("typed scalar changed on encoding")
		}
	}
}
