// Copyright (C) 2026 The go-matter Authors. Licensed under the Apache License, Version 2.0.

package tui

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cybergarage/go-matter/matter"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	"github.com/cybergarage/go-matter/matter/protocol/im"
	"github.com/gdamore/tcell/v2"
)

type partialInventory struct{ simulatedInventory }

func (partialInventory) scalar(ep im.EndpointID, cl im.ClusterID, a im.AttributeID) (uint64, error) {
	if cl == 6 && a == 0xFFFD {
		return 5, nil
	}
	return simulatedInventory{}.scalar(ep, cl, a)
}
func (partialInventory) ids(ep im.EndpointID, cl im.ClusterID, a im.AttributeID) ([]uint32, error) {
	if cl == 6 && a == 0xFFF9 {
		return nil, errors.New("fictional command list denied")
	}
	if cl == 0x28 && a == 0xFFFB {
		return nil, errors.New("fictional attribute list denied")
	}
	return simulatedInventory{}.ids(ep, cl, a)
}
func TestInventoryUsesObservedIDsWithoutInferringPermission(t *testing.T) {
	r, err := inspectInventory(partialInventory{})
	if err != nil {
		t.Fatal(err)
	}
	var commandRows, unknown, missing, revision bool
	for _, p := range r.Paths {
		if p.Cluster == 6 && len(p.Commands) > 0 {
			t.Fatal("failed discovery enabled legacy commands")
		}
		if p.Cluster == 6 && p.Kind == "command" {
			commandRows = true
		}
		if p.Cluster == 6 && strings.Contains(pathDetail(p), "REVISION MISMATCH") {
			revision = true
		}
		if p.Cluster == 0xFFF10001 && p.Attribute == 0xABCD && p.Kind == "" {
			unknown = strings.Contains(p.String(), "0xFFF10001") && strings.Contains(p.String(), "0x0000ABCD")
		}
		if p.Cluster == 0x28 && p.Kind == "cluster" {
			missing = strings.Contains(pathDetail(p), "AttributeList: UNAVAILABLE / ERROR")
		}
		if p.Cluster == 0x28 && p.Kind == "" {
			t.Fatal("dictionary-only attributes invented")
		}
	}
	if commandRows || !unknown || !missing || !revision {
		t.Fatalf("partial inventory lost distinctions: %t %t %t %t", commandRows, unknown, missing, revision)
	}
}

type valueNode struct {
	matter.Node
	value  tlv.Element
	status *im.InvokeStatus
	fail   bool
}

func (n valueNode) ReadAttribute(_ im.EndpointID, _ im.ClusterID, _ im.AttributeID) (*im.ReadResponse, error) {
	if n.fail {
		return nil, errors.New("fictional read failure")
	}
	return &im.ReadResponse{Value: n.value, Status: n.status}, nil
}
func scalar(t *testing.T, put func(tlv.Encoder)) tlv.Element {
	t.Helper()
	enc := tlv.NewEncoder()
	put(enc)
	dec := tlv.NewDecoderWithBytes(enc.Bytes())
	if !dec.Next() {
		t.Fatal(dec.Error())
	}
	return dec.Element()
}
func TestTypedRawObservationsAndErrors(t *testing.T) {
	tests := []struct {
		put  func(tlv.Encoder)
		want string
	}{
		{func(e tlv.Encoder) { e.PutSigned2(tlv.NewAnonymousTag(), -500) }, "-500"},
		{func(e tlv.Encoder) { e.PutUnsigned8(tlv.NewAnonymousTag(), 0xFFFFFFFFFFFFFFFF) }, "18446744073709551615"},
		{func(e tlv.Encoder) { e.PutBool(tlv.NewAnonymousTag(), true) }, "true"},
		{func(e tlv.Encoder) { e.PutNull(tlv.NewAnonymousTag()) }, "null"},
		{func(e tlv.Encoder) { _ = e.PutOctet(tlv.NewAnonymousTag(), []byte{0, 255}) }, "0x00FF"},
		{func(e tlv.Encoder) { _ = e.PutUTF8(tlv.NewAnonymousTag(), "fictional [red] value") }, `"fictional [red] value"`},
	}
	for _, test := range tests {
		p := Path{Endpoint: 1, Cluster: 0x402, Attribute: 0}
		r, err := readNode(valueNode{value: scalar(t, test.put)}, p)
		if err != nil || !strings.Contains(r.Message, test.want) || !strings.Contains(r.Message, "Raw decoded TLV value") || !strings.Contains(r.Message, "Received at:") || !strings.Contains(r.Message, "Type: temperature") {
			t.Fatalf("observation: %v / %s", err, r.Message)
		}
		if strings.Contains(r.Message, "°C") {
			t.Fatal("unit/scale inferred without imported definition")
		}
	}
	for _, status := range []struct {
		code  im.Status
		label string
	}{{im.StatusUnsupportedAttribute, "UNSUPPORTED"}, {im.StatusUnsupportedAccess, "ACCESS DENIED"}} {
		_, err := readNode(valueNode{status: &im.InvokeStatus{IMStatus: uint8(status.code)}}, Path{})
		if err == nil || !strings.Contains(err.Error(), status.label) {
			t.Fatalf("status lost: %v", err)
		}
	}
	_, err := readNode(valueNode{fail: true}, Path{})
	if err == nil || !strings.Contains(err.Error(), "ERROR") {
		t.Fatal("error treated as value")
	}
}
func TestNestedListPreservesFieldsAndRejectsTruncation(t *testing.T) {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	enc.PutUnsigned4(tlv.NewContextTag(0), 0x100)
	enc.PutUnsigned2(tlv.NewContextTag(1), 3)
	_ = enc.EndContainer()
	dec := tlv.NewDecoderWithBytes(enc.Bytes())
	dec.Next()
	value, err := listValue(dec, dec.Element(), 0)
	if err != nil || !strings.Contains(value, "256") || !strings.Contains(value, "3") {
		t.Fatalf("list fields lost: %s %v", value, err)
	}
	dec = tlv.NewDecoderWithBytes(enc.Bytes()[:len(enc.Bytes())-1])
	dec.Next()
	if _, err = listValue(dec, dec.Element(), 0); err == nil {
		t.Fatal("truncated struct accepted")
	}
}

type twoDevices struct {
	Demo
	failList bool
}

func (b *twoDevices) List() ([]Device, error) {
	if b.failList {
		return nil, errors.New("fixture list failed")
	}
	return []Device{{ID: 1, Name: "First fictional node"}, {ID: 2, Name: "Second fictional node"}}, nil
}
func TestSelectionAndFailedInventoryDiscardOldValuesAndActions(t *testing.T) {
	u, _ := newTestUI(t)
	backend := &twoDevices{}
	u.backend = backend
	u.reload()
	u.start(true, time.Second, func(ctx context.Context) (Result, error) { return backend.Inspect(ctx, 1) })
	waitWork(t, u)
	if len(u.inventory) == 0 {
		t.Fatal("fixture missing")
	}
	u.detail.SetText("OLD DEVICE VALUE")
	u.devices.SetCurrentItem(1)
	if d, ok := u.device(); !ok || d.ID != 2 {
		t.Fatal("changed callback retained previous device")
	}
	if len(u.inventory) != 0 || u.paths.GetItemCount() != 0 || strings.Contains(u.detail.GetText(false), "OLD DEVICE") {
		t.Fatal("old device data retained")
	}
	u.start(true, time.Second, func(context.Context) (Result, error) { return Result{}, errors.New("new inspection failed") })
	waitWork(t, u)
	if len(u.inventory) != 0 || u.paths.GetItemCount() != 0 {
		t.Fatal("failed inspection retained paths or commands")
	}
	backend.failList = true
	u.reload()
	if len(u.visible) != 0 || len(u.records) != 0 || len(u.inventory) != 0 {
		t.Fatal("failed reload retained old nodes")
	}
}
func TestDelayedOldCompletionAndStaleConfirmationCannotApply(t *testing.T) {
	u, _ := newTestUI(t)
	backend := &twoDevices{}
	u.backend = backend
	u.reload()
	done := make(chan struct{})
	u.start(true, time.Second, func(context.Context) (Result, error) {
		<-done
		return Result{Message: "STALE", Paths: []Path{{Cluster: 6, Commands: []im.CommandID{1}}}}, nil
	})
	u.devices.SetCurrentItem(1)
	close(done)
	waitWork(t, u)
	if len(u.inventory) != 0 || strings.Contains(u.detail.GetText(false), "STALE") {
		t.Fatal("old completion applied to new node")
	}
	called := false
	u.confirm("fixture confirmation", func() { called = true })
	u.devices.SetCurrentItem(0)
	press(u, tcell.KeyRight, 0)
	press(u, tcell.KeyEnter, 0)
	if called {
		t.Fatal("stale confirmation executed")
	}
}
func TestReadPreservesInventoryAndPathSwitchClearsObservation(t *testing.T) {
	u, s := newTestUI(t)
	r, _ := u.backend.Inspect(context.Background(), 0x101)
	u.inventory = r.Paths
	for _, p := range r.Paths {
		u.paths.AddItem(p.String(), "", 0, nil)
	}
	var index int
	for i, p := range u.inventory {
		if p.Kind == "" && p.Cluster == 6 && p.Attribute == 0 {
			index = i
			break
		}
	}
	u.paths.SetCurrentItem(index)
	p, _ := u.path()
	count := len(u.inventory)
	if len(p.Commands) != 3 {
		t.Fatal("correct row selection not applied")
	}
	u.start(false, time.Second, func(ctx context.Context) (Result, error) { return u.backend.Read(ctx, 0x101, p) })
	waitWork(t, u)
	if len(u.inventory) != count || !strings.Contains(u.detail.GetText(false), "FRESH READ") {
		t.Fatal("read cleared inventory")
	}
	u.paths.SetCurrentItem(index + 1)
	if strings.Contains(u.detail.GetText(false), "FRESH READ") || !strings.Contains(u.detail.GetText(false), "NOT FETCHED") {
		t.Fatal("previous attribute value retained")
	}
	u.start(false, time.Second, func(context.Context) (Result, error) { return Result{}, errors.New("ERROR: fixture read failed") })
	waitWork(t, u)
	if strings.Contains(u.detail.GetText(false), "Value: true") || !strings.Contains(u.detail.GetText(false), "ERROR") {
		t.Fatal("failure retained old value")
	}
	u.paths.SetCurrentItem(index)
	u.detail.SetText(pathDetail(p))
	screenshot(t, u, s, "tui-metadata")
	r, _ = u.backend.Read(context.Background(), 0x101, p)
	u.detail.SetText(r.Message)
	screenshot(t, u, s, "tui-observation")
	s.SetSize(60, 24)
	screenshot(t, u, s, "tui-metadata-compact")
}
