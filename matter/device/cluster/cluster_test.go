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

package cluster

import (
	"sync"
	"testing"
	"time"

	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	"github.com/cybergarage/go-matter/matter/protocol/im"
)

type attrKey struct {
	cluster   im.ClusterID
	attribute im.AttributeID
}

type cmdKey struct {
	cluster im.ClusterID
	command im.CommandID
}

// fakeEndpoint records what a cluster registers and which attributes it
// reports changed.
type fakeEndpoint struct {
	mutex    sync.Mutex
	fabric   uint8
	removed  []func(uint8)
	sessions map[attrKey]im.AttributeReadHandler
	readers  map[attrKey]im.AttributeReader
	writers  map[attrKey]im.AttributeWriteHandler
	commands map[cmdKey]im.CommandHandler
	changed  []attrKey
}

func newFakeEndpoint() *fakeEndpoint {
	return &fakeEndpoint{
		mutex:    sync.Mutex{},
		fabric:   1,
		removed:  nil,
		sessions: map[attrKey]im.AttributeReadHandler{},
		readers:  map[attrKey]im.AttributeReader{},
		writers:  map[attrKey]im.AttributeWriteHandler{},
		commands: map[cmdKey]im.CommandHandler{},
		changed:  nil,
	}
}

func (ep *fakeEndpoint) HandleAttribute(c im.ClusterID, a im.AttributeID, r im.AttributeReader, _ ...im.HandlerOption) {
	ep.readers[attrKey{c, a}] = r
}

func (ep *fakeEndpoint) HandleAttributeRead(c im.ClusterID, a im.AttributeID, h im.AttributeReadHandler, _ ...im.HandlerOption) {
	ep.sessions[attrKey{c, a}] = h
}

func (ep *fakeEndpoint) AccessingFabric(im.SecureSession) uint8 {
	return ep.fabric
}

func (ep *fakeEndpoint) HandleFabricRemoved(h func(uint8)) {
	ep.removed = append(ep.removed, h)
}

func (ep *fakeEndpoint) HandleAttributeWrite(c im.ClusterID, a im.AttributeID, h im.AttributeWriteHandler, _ ...im.HandlerOption) {
	ep.writers[attrKey{c, a}] = h
}

func (ep *fakeEndpoint) HandleCommand(c im.ClusterID, cmd im.CommandID, h im.CommandHandler, _ ...im.HandlerOption) {
	ep.commands[cmdKey{c, cmd}] = h
}

func (ep *fakeEndpoint) NotifyAttributeChanged(c im.ClusterID, a im.AttributeID) {
	ep.mutex.Lock()
	defer ep.mutex.Unlock()
	ep.changed = append(ep.changed, attrKey{c, a})
}

func (ep *fakeEndpoint) takeChanged() []attrKey {
	ep.mutex.Lock()
	defer ep.mutex.Unlock()
	changed := ep.changed
	ep.changed = nil
	return changed
}

func (ep *fakeEndpoint) read(t *testing.T, c im.ClusterID, a im.AttributeID) tlv.Element {
	t.Helper()
	r, ok := ep.readers[attrKey{c, a}]
	if !ok {
		t.Fatalf("attribute 0x%04X/0x%04X is not served", c, a)
	}
	enc := tlv.NewEncoder()
	if status := r(enc, tlv.NewAnonymousTag()); status != im.StatusSuccess {
		t.Fatalf("read 0x%04X/0x%04X: status %#x", c, a, uint8(status))
	}
	dec := tlv.NewDecoderWithBytes(enc.Bytes())
	if !dec.Next() {
		t.Fatalf("read 0x%04X/0x%04X: no value", c, a)
	}
	return dec.Element()
}

func (ep *fakeEndpoint) write(t *testing.T, c im.ClusterID, a im.AttributeID, put func(tlv.Encoder, tlv.Tag)) im.Status {
	t.Helper()
	h, ok := ep.writers[attrKey{c, a}]
	if !ok {
		t.Fatalf("attribute 0x%04X/0x%04X is not writable", c, a)
	}
	enc := tlv.NewEncoder()
	put(enc, tlv.NewAnonymousTag())
	return h(&im.AttributeWriteRequest{Data: enc.Bytes()})
}

// invoke calls a command with unsigned fields by context tag.
func (ep *fakeEndpoint) invoke(t *testing.T, c im.ClusterID, cmd im.CommandID, fields map[uint8]uint64) im.CommandResult {
	t.Helper()
	return ep.invokeWith(t, c, cmd, func(enc tlv.Encoder) {
		for tag, v := range fields {
			if err := enc.PutUnsigned(tlv.NewContextTag(tag), v); err != nil {
				t.Fatal(err)
			}
		}
	})
}

// invokeWith calls a command with the fields put encodes.
func (ep *fakeEndpoint) invokeWith(t *testing.T, c im.ClusterID, cmd im.CommandID, put func(enc tlv.Encoder)) im.CommandResult {
	t.Helper()
	h, ok := ep.commands[cmdKey{c, cmd}]
	if !ok {
		t.Fatalf("command 0x%04X/0x%02X is not served", c, cmd)
	}
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	put(enc)
	if err := enc.EndContainer(); err != nil {
		t.Fatal(err)
	}
	req := &im.CommandRequest{Endpoint: 1, Cluster: c, Command: cmd, Fields: map[uint8]tlv.Element{}, Data: enc.Bytes()}
	dec := tlv.NewDecoderWithBytes(enc.Bytes())
	dec.Next()
	depth := 1
	for depth > 0 && dec.Next() {
		elem := dec.Element()
		switch {
		case elem.Type().IsEndOfContainer():
			depth--
			continue
		case depth == 1:
			if ct, ok := elem.Tag().(tlv.ContextTag); ok {
				req.Fields[uint8(ct.ContextNumber())] = elem
			}
		}
		if elem.Type().IsContainer() {
			depth++
		}
	}
	return h(req)
}

func boolOf(t *testing.T, elem tlv.Element) bool {
	t.Helper()
	v, ok := elem.Bool()
	if !ok {
		t.Fatalf("%v is not a boolean", elem)
	}
	return v
}

func TestOnOff(t *testing.T) {
	var mutex sync.Mutex
	var calls []bool
	c := NewOnOff(WithOnOffHandler(func(on bool) {
		mutex.Lock()
		defer mutex.Unlock()
		calls = append(calls, on)
	}))
	ep := newFakeEndpoint()
	c.Register(ep)

	if boolOf(t, ep.read(t, OnOffClusterID, OnOffAttributeID)) {
		t.Fatal("OnOff starts on")
	}
	if v, _ := ep.read(t, OnOffClusterID, featureMapAttributeID).Unsigned(); v != uint64(OnOffFeatureLighting) {
		t.Fatalf("FeatureMap = %#x, want Lighting", v)
	}
	onOff := attrKey{OnOffClusterID, OnOffAttributeID}
	for _, tc := range []struct {
		command im.CommandID
		want    bool
		changed bool
	}{
		{OnCommandID, true, true},
		{OnCommandID, true, false},
		{ToggleCommandID, false, true},
		{ToggleCommandID, true, true},
		{OffCommandID, false, true},
	} {
		if r := ep.invoke(t, OnOffClusterID, tc.command, nil); r.Status != im.StatusSuccess {
			t.Fatalf("command 0x%02X: status %#x", tc.command, uint8(r.Status))
		}
		if got := boolOf(t, ep.read(t, OnOffClusterID, OnOffAttributeID)); got != tc.want {
			t.Fatalf("after command 0x%02X OnOff = %v, want %v", tc.command, got, tc.want)
		}
		changed := ep.takeChanged()
		if tc.changed != (len(changed) == 1 && changed[0] == onOff) {
			t.Fatalf("after command 0x%02X reported %v", tc.command, changed)
		}
	}
	mutex.Lock()
	if len(calls) != 4 {
		t.Fatalf("handler calls = %v, want one per change", calls)
	}
	mutex.Unlock()

	// OnWithTimedOff with AcceptOnlyWhenOn does nothing while off.
	ep.invoke(t, OnOffClusterID, OnWithTimedOffCommandID, map[uint8]uint64{0: 1, 1: 1, 2: 0})
	if c.On() {
		t.Fatal("OnWithTimedOff(AcceptOnlyWhenOn) turned an off light on")
	}
	ep.invoke(t, OnOffClusterID, OnWithTimedOffCommandID, map[uint8]uint64{0: 0, 1: 1, 2: 0})
	if !c.On() {
		t.Fatal("OnWithTimedOff did not turn on")
	}
	deadline := time.Now().Add(2 * time.Second)
	for c.On() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if c.On() {
		t.Fatal("OnWithTimedOff did not turn off after OnTime")
	}

	if v := ep.read(t, OnOffClusterID, StartUpOnOffAttributeID); !v.Type().IsNull() {
		t.Fatalf("StartUpOnOff = %v, want null", v)
	}
	if s := ep.write(t, OnOffClusterID, StartUpOnOffAttributeID, func(enc tlv.Encoder, tag tlv.Tag) { enc.PutUnsigned1(tag, 3) }); s != im.StatusConstraintError {
		t.Fatalf("write StartUpOnOff 3: status %#x, want CONSTRAINT_ERROR", uint8(s))
	}
	if s := ep.write(t, OnOffClusterID, StartUpOnOffAttributeID, func(enc tlv.Encoder, tag tlv.Tag) { enc.PutUnsigned1(tag, 1) }); s != im.StatusSuccess {
		t.Fatalf("write StartUpOnOff 1: status %#x", uint8(s))
	}
	if v, _ := ep.read(t, OnOffClusterID, StartUpOnOffAttributeID).Unsigned(); v != 1 {
		t.Fatalf("StartUpOnOff = %d, want 1", v)
	}
}

func TestIdentify(t *testing.T) {
	events := make(chan bool, 4)
	c := NewIdentify(IdentifyTypeLightOutput, WithIdentifyHandler(func(identifying bool) { events <- identifying }))
	ep := newFakeEndpoint()
	c.Register(ep)

	if v, _ := ep.read(t, IdentifyClusterID, IdentifyTypeAttributeID).Unsigned(); v != uint64(IdentifyTypeLightOutput) {
		t.Fatalf("IdentifyType = %d", v)
	}
	ep.invoke(t, IdentifyClusterID, IdentifyCommandID, map[uint8]uint64{0: 1})
	if !<-events {
		t.Fatal("Identify did not start identifying")
	}
	if v, _ := ep.read(t, IdentifyClusterID, IdentifyTimeAttributeID).Unsigned(); v != 1 {
		t.Fatalf("IdentifyTime = %d, want 1", v)
	}
	select {
	case identifying := <-events:
		if identifying {
			t.Fatal("identification restarted")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("identification did not stop when IdentifyTime ran out")
	}
	if v, _ := ep.read(t, IdentifyClusterID, IdentifyTimeAttributeID).Unsigned(); v != 0 {
		t.Fatalf("IdentifyTime = %d after it ran out", v)
	}

	if s := ep.write(t, IdentifyClusterID, IdentifyTimeAttributeID, func(enc tlv.Encoder, tag tlv.Tag) { enc.PutUnsigned2(tag, 60) }); s != im.StatusSuccess {
		t.Fatalf("write IdentifyTime: status %#x", uint8(s))
	}
	if !<-events {
		t.Fatal("writing IdentifyTime did not start identifying")
	}
	ep.invoke(t, IdentifyClusterID, IdentifyCommandID, map[uint8]uint64{0: 0})
	if <-events {
		t.Fatal("Identify(0) did not stop identifying")
	}
}

func TestGroups(t *testing.T) {
	ep := newFakeEndpoint()
	NewGroups().Register(ep)

	for _, tc := range []struct {
		command im.CommandID
		group   uint64
		want    im.Status
	}{
		{AddGroupCommandID, 1, im.StatusUnsupportedAccess},
		{AddGroupCommandID, 0, im.StatusConstraintError},
		{ViewGroupCommandID, 1, im.StatusNotFound},
		{RemoveGroupCommandID, 1, im.StatusNotFound},
	} {
		r := ep.invoke(t, GroupsClusterID, tc.command, map[uint8]uint64{0: tc.group})
		if r.ResponseCommand != tc.command {
			t.Fatalf("command 0x%02X answered with 0x%02X", tc.command, r.ResponseCommand)
		}
		dec := tlv.NewDecoderWithBytes(r.Fields)
		dec.Next()
		dec.Next()
		if v, _ := dec.Element().Unsigned(); v != uint64(tc.want) {
			t.Fatalf("command 0x%02X group %d: status %#x, want %#x", tc.command, tc.group, v, uint8(tc.want))
		}
	}
	if r := ep.invoke(t, GroupsClusterID, RemoveAllGroupsCommandID, nil); r.Status != im.StatusSuccess {
		t.Fatalf("RemoveAllGroups: status %#x", uint8(r.Status))
	}
}
