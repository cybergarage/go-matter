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
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/cybergarage/go-matter/matter/device"
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
	mutex   sync.Mutex
	fabric  uint8
	removed []func(uint8)
	// mapped are the groups with a key set; groups those the endpoint is
	// in, by name.
	mapped   map[uint16]bool
	groups   map[uint16]string
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
		mapped:   map[uint16]bool{},
		groups:   map[uint16]string{},
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

func (ep *fakeEndpoint) JoinGroup(_ uint8, group uint16, name string) im.Status {
	if !ep.mapped[group] {
		return im.StatusUnsupportedAccess
	}
	if _, ok := ep.groups[group]; !ok && device.MaxGroupsPerFabric <= len(ep.groups) {
		return im.StatusResourceExhausted
	}
	ep.groups[group] = name
	return im.StatusSuccess
}

func (ep *fakeEndpoint) LeaveGroup(_ uint8, group uint16) im.Status {
	if _, ok := ep.groups[group]; !ok {
		return im.StatusNotFound
	}
	delete(ep.groups, group)
	return im.StatusSuccess
}

func (ep *fakeEndpoint) LeaveAllGroups(uint8) []uint16 {
	left := make([]uint16, 0, len(ep.groups))
	for g := range ep.groups {
		left = append(left, g)
	}
	clear(ep.groups)
	return left
}

func (ep *fakeEndpoint) Groups(uint8) []device.GroupMembership {
	groups := make([]device.GroupMembership, 0, len(ep.groups))
	for g, name := range ep.groups {
		groups = append(groups, device.GroupMembership{GroupID: g, Name: name})
	}
	slices.SortFunc(groups, func(a, b device.GroupMembership) int { return int(a.GroupID) - int(b.GroupID) })
	return groups
}

func (ep *fakeEndpoint) GroupCapacity(uint8) int {
	return device.MaxGroupsPerFabric - len(ep.groups)
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
	var removed []uint16
	NewGroups(WithGroupsRemovedHandler(func(_ uint8, groups []uint16) { removed = append(removed, groups...) })).Register(ep)
	ep.mapped[1] = true
	ep.mapped[2] = true

	addGroup := func(group uint16, name string) im.CommandResult {
		return ep.invokeWith(t, GroupsClusterID, AddGroupCommandID, func(enc tlv.Encoder) {
			enc.PutUnsigned2(tlv.NewContextTag(0), group)
			_ = enc.PutUTF8(tlv.NewContextTag(1), name)
		})
	}
	status := func(r im.CommandResult) uint64 {
		t.Helper()
		if !r.HasResponse {
			t.Fatalf("no response, status %#x", uint8(r.Status))
		}
		dec := tlv.NewDecoderWithBytes(r.Fields)
		dec.Next()
		dec.Next()
		v, _ := dec.Element().Unsigned()
		return v
	}
	for _, tc := range []struct {
		group uint16
		name  string
		want  im.Status
	}{
		{1, "Kitchen", im.StatusSuccess},
		{0, "", im.StatusConstraintError},
		{3, "", im.StatusUnsupportedAccess},
		{2, "a name longer than sixteen", im.StatusConstraintError},
	} {
		if got := status(addGroup(tc.group, tc.name)); got != uint64(tc.want) {
			t.Errorf("AddGroup(%d, %q): status %#x, want %#x", tc.group, tc.name, got, uint8(tc.want))
		}
	}
	view := ep.invoke(t, GroupsClusterID, ViewGroupCommandID, map[uint8]uint64{0: 1})
	if status(view) != 0 {
		t.Fatalf("ViewGroup(1): status %#x", status(view))
	}
	if ep.groups[1] != "Kitchen" {
		t.Fatalf("group 1 is named %q", ep.groups[1])
	}
	if s := status(ep.invoke(t, GroupsClusterID, ViewGroupCommandID, map[uint8]uint64{0: 2})); s != uint64(im.StatusNotFound) {
		t.Fatalf("ViewGroup(2): status %#x, want NOT_FOUND", s)
	}

	membership := ep.invokeWith(t, GroupsClusterID, GetGroupMembershipCommandID, func(enc tlv.Encoder) {
		enc.BeginArray(tlv.NewContextTag(0))
		_ = enc.EndContainer()
	})
	dec := tlv.NewDecoderWithBytes(membership.Fields)
	dec.Next()
	dec.Next()
	if capacity, _ := dec.Element().Unsigned(); capacity != device.MaxGroupsPerFabric-1 {
		t.Fatalf("GetGroupMembership capacity = %d", capacity)
	}
	dec.Next() // GroupList
	dec.Next()
	if g, _ := dec.Element().Unsigned(); g != 1 {
		t.Fatalf("GetGroupMembership lists group %d, want 1", g)
	}

	if s := status(ep.invoke(t, GroupsClusterID, RemoveGroupCommandID, map[uint8]uint64{0: 1})); s != 0 {
		t.Fatalf("RemoveGroup(1): status %#x", s)
	}
	if s := status(ep.invoke(t, GroupsClusterID, RemoveGroupCommandID, map[uint8]uint64{0: 1})); s != uint64(im.StatusNotFound) {
		t.Fatalf("RemoveGroup(1) twice: status %#x, want NOT_FOUND", s)
	}
	addGroup(2, "")
	if r := ep.invoke(t, GroupsClusterID, RemoveAllGroupsCommandID, nil); r.Status != im.StatusSuccess {
		t.Fatalf("RemoveAllGroups: status %#x", uint8(r.Status))
	}
	if !slices.Equal(removed, []uint16{1, 2}) || len(ep.groups) != 0 {
		t.Fatalf("the groups removed were %v, the endpoint is left in %v", removed, ep.groups)
	}

	// AddGroupIfIdentifying adds only while identifying.
	identify := NewIdentify(IdentifyTypeLightOutput)
	identify.Register(ep)
	ep2 := newFakeEndpoint()
	ep2.mapped[1] = true
	NewGroups(WithGroupsIdentify(identify)).Register(ep2)
	addIfIdentifying := func() im.CommandResult {
		return ep2.invokeWith(t, GroupsClusterID, AddGroupIfIdentifyingCommandID, func(enc tlv.Encoder) {
			enc.PutUnsigned2(tlv.NewContextTag(0), 1)
			_ = enc.PutUTF8(tlv.NewContextTag(1), "")
		})
	}
	if r := addIfIdentifying(); r.Status != im.StatusSuccess || len(ep2.groups) != 0 {
		t.Fatalf("AddGroupIfIdentifying while not identifying: (%#x, %v)", uint8(r.Status), ep2.groups)
	}
	ep.invoke(t, IdentifyClusterID, IdentifyCommandID, map[uint8]uint64{0: 10})
	if r := addIfIdentifying(); r.Status != im.StatusSuccess || len(ep2.groups) != 1 {
		t.Fatalf("AddGroupIfIdentifying while identifying: (%#x, %v)", uint8(r.Status), ep2.groups)
	}
}
