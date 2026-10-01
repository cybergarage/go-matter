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
	"testing"

	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	"github.com/cybergarage/go-matter/matter/protocol/im"
)

// responseFields decodes the top-level fields of a response command.
func responseFields(t *testing.T, r im.CommandResult) map[uint8]tlv.Element {
	t.Helper()
	if !r.HasResponse {
		t.Fatalf("no response command, status %#x", uint8(r.Status))
	}
	fields := map[uint8]tlv.Element{}
	dec := tlv.NewDecoderWithBytes(r.Fields)
	dec.Next()
	depth := 1
	for depth > 0 && dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			depth--
			continue
		}
		if depth == 1 {
			if tag, ok := contextTag(elem); ok {
				fields[tag] = elem
			}
		}
		if elem.Type().IsContainer() {
			depth++
		}
	}
	return fields
}

func responseStatus(t *testing.T, r im.CommandResult) im.Status {
	t.Helper()
	v, _ := responseFields(t, r)[0].Unsigned()
	return im.Status(v)
}

// putAddScene encodes the fields of an AddScene of the OnOff attribute.
func putAddScene(group uint16, scene uint8, name string, on uint8) func(enc tlv.Encoder) {
	return func(enc tlv.Encoder) {
		enc.PutUnsigned2(tlv.NewContextTag(0), group)
		enc.PutUnsigned1(tlv.NewContextTag(1), scene)
		enc.PutUnsigned4(tlv.NewContextTag(2), 1000)
		_ = enc.PutUTF8(tlv.NewContextTag(3), name)
		enc.BeginArray(tlv.NewContextTag(4))
		for _, cluster := range []im.ClusterID{OnOffClusterID, 0x0300} {
			enc.BeginStructure(tlv.NewAnonymousTag())
			enc.PutUnsigned4(tlv.NewContextTag(0), uint32(cluster))
			enc.BeginArray(tlv.NewContextTag(1))
			enc.BeginStructure(tlv.NewAnonymousTag())
			enc.PutUnsigned4(tlv.NewContextTag(0), uint32(OnOffAttributeID))
			enc.PutUnsigned1(tlv.NewContextTag(1), on)
			_ = enc.EndContainer()
			_ = enc.EndContainer()
			_ = enc.EndContainer()
		}
		_ = enc.EndContainer()
	}
}

func sceneInfo(t *testing.T, ep *fakeEndpoint) map[uint8]tlv.Element {
	t.Helper()
	enc := tlv.NewEncoder()
	h := ep.sessions[attrKey{ScenesManagementClusterID, FabricSceneInfoAttributeID}]
	if status := h(&im.AttributeRequest{Session: nil, Path: im.AttributePath{Endpoint: 1, Cluster: ScenesManagementClusterID, Attribute: FabricSceneInfoAttributeID}, FabricFiltered: true}, enc, tlv.NewAnonymousTag()); status != im.StatusSuccess {
		t.Fatalf("read FabricSceneInfo: status %#x", uint8(status))
	}
	fields := map[uint8]tlv.Element{}
	dec := tlv.NewDecoderWithBytes(enc.Bytes())
	dec.Next() // the list
	if !dec.Next() || !dec.Element().Type().IsStructure() {
		t.Fatal("FabricSceneInfo has no entry for the accessing fabric")
	}
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			break
		}
		tag, _ := contextTag(elem)
		fields[tag] = elem
	}
	return fields
}

func unsignedOf(e tlv.Element) uint64 {
	v, _ := e.Unsigned()
	return v
}

func TestScenes(t *testing.T) {
	ep := newFakeEndpoint()
	light := NewOnOff()
	light.Register(ep)
	scenes := NewScenes()
	scenes.AddSceneHandler(OnOffClusterID, light)
	scenes.Register(ep)

	// AddScene keeps the extensions of the endpoint's clusters only.
	if s := responseStatus(t, ep.invokeWith(t, ScenesManagementClusterID, AddSceneCommandID, putAddScene(0, 1, "Evening", 1))); s != im.StatusSuccess {
		t.Fatalf("AddScene: status %#x", uint8(s))
	}
	view := responseFields(t, ep.invoke(t, ScenesManagementClusterID, ViewSceneCommandID, map[uint8]uint64{0: 0, 1: 1}))
	if unsignedOf(view[0]) != 0 || unsignedOf(view[3]) != 1000 {
		t.Fatalf("ViewScene = %v", view)
	}
	if name, _ := view[4].UTF8(); name != "Evening" {
		t.Fatalf("ViewScene name = %q", name)
	}
	if s := responseStatus(t, ep.invokeWith(t, ScenesManagementClusterID, AddSceneCommandID, putAddScene(5, 1, "", 1))); s != im.StatusInvalidCommand {
		t.Fatalf("AddScene in a group the endpoint is not in: status %#x, want INVALID_COMMAND", uint8(s))
	}
	ep.mapped[5] = true
	ep.JoinGroup(1, 5, "")
	if s := responseStatus(t, ep.invokeWith(t, ScenesManagementClusterID, AddSceneCommandID, putAddScene(5, 1, "", 1))); s != im.StatusSuccess {
		t.Fatalf("AddScene in a group the endpoint is in: status %#x", uint8(s))
	}
	scenes.RemoveGroups(1, []uint16{5})
	if s := responseStatus(t, ep.invoke(t, ScenesManagementClusterID, ViewSceneCommandID, map[uint8]uint64{0: 5, 1: 1})); s != im.StatusNotFound {
		t.Fatalf("ViewScene of a removed group's scene: status %#x, want NOT_FOUND", uint8(s))
	}
	ep.LeaveGroup(1, 5)
	if s := responseStatus(t, ep.invokeWith(t, ScenesManagementClusterID, AddSceneCommandID, putAddScene(0, 0xFF, "", 1))); s != im.StatusConstraintError {
		t.Fatalf("AddScene of scene 0xFF: status %#x, want CONSTRAINT_ERROR", uint8(s))
	}

	// RecallScene sets OnOff, and the scene is the valid current one.
	if r := ep.invoke(t, ScenesManagementClusterID, RecallSceneCommandID, map[uint8]uint64{0: 0, 1: 1}); r.Status != im.StatusSuccess {
		t.Fatalf("RecallScene: status %#x", uint8(r.Status))
	}
	if !light.On() {
		t.Fatal("recalling the scene did not turn the light on")
	}
	info := sceneInfo(t, ep)
	if unsignedOf(info[0]) != 1 || unsignedOf(info[1]) != 1 || unsignedOf(info[4]) != scenesPerFabric-1 {
		t.Fatalf("FabricSceneInfo = %v", info)
	}
	if valid, _ := info[3].Bool(); !valid {
		t.Fatal("the recalled scene is not valid")
	}
	// Switching the light leaves the scene invalid.
	light.Set(false)
	if valid, _ := sceneInfo(t, ep)[3].Bool(); valid {
		t.Fatal("the scene stayed valid after the light changed")
	}

	// StoreScene stores the light as it is.
	if s := responseStatus(t, ep.invoke(t, ScenesManagementClusterID, StoreSceneCommandID, map[uint8]uint64{0: 0, 1: 2})); s != im.StatusSuccess {
		t.Fatalf("StoreScene: status %#x", uint8(s))
	}
	light.Set(true)
	ep.invoke(t, ScenesManagementClusterID, RecallSceneCommandID, map[uint8]uint64{0: 0, 1: 2})
	if light.On() {
		t.Fatal("recalling the stored scene did not turn the light off")
	}
	if r := ep.invoke(t, ScenesManagementClusterID, RecallSceneCommandID, map[uint8]uint64{0: 0, 1: 9}); r.Status != im.StatusNotFound {
		t.Fatalf("RecallScene of a missing scene: status %#x, want NOT_FOUND", uint8(r.Status))
	}

	membership := responseFields(t, ep.invoke(t, ScenesManagementClusterID, GetSceneMembershipCommandID, map[uint8]uint64{0: 0}))
	if unsignedOf(membership[0]) != 0 || unsignedOf(membership[1]) != scenesPerFabric-2 {
		t.Fatalf("GetSceneMembership = %v", membership)
	}

	// The fabric fills its share of the table.
	for scene := uint8(3); scene < 3+scenesPerFabric-2; scene++ {
		if s := responseStatus(t, ep.invoke(t, ScenesManagementClusterID, StoreSceneCommandID, map[uint8]uint64{0: 0, 1: uint64(scene)})); s != im.StatusSuccess {
			t.Fatalf("StoreScene %d: status %#x", scene, uint8(s))
		}
	}
	if s := responseStatus(t, ep.invoke(t, ScenesManagementClusterID, StoreSceneCommandID, map[uint8]uint64{0: 0, 1: 100})); s != im.StatusResourceExhausted {
		t.Fatalf("StoreScene beyond the fabric's share: status %#x, want RESOURCE_EXHAUSTED", uint8(s))
	}

	if s := responseStatus(t, ep.invoke(t, ScenesManagementClusterID, RemoveSceneCommandID, map[uint8]uint64{0: 0, 1: 1})); s != im.StatusSuccess {
		t.Fatalf("RemoveScene: status %#x", uint8(s))
	}
	if s := responseStatus(t, ep.invoke(t, ScenesManagementClusterID, RemoveSceneCommandID, map[uint8]uint64{0: 0, 1: 1})); s != im.StatusNotFound {
		t.Fatalf("RemoveScene twice: status %#x, want NOT_FOUND", uint8(s))
	}
	if s := responseStatus(t, ep.invoke(t, ScenesManagementClusterID, RemoveAllScenesCommandID, map[uint8]uint64{0: 0})); s != im.StatusSuccess {
		t.Fatalf("RemoveAllScenes: status %#x", uint8(s))
	}
	if n := unsignedOf(sceneInfo(t, ep)[0]); n != 0 {
		t.Fatalf("SceneCount = %d after RemoveAllScenes", n)
	}

	// The scenes of a removed fabric go with it.
	ep.invokeWith(t, ScenesManagementClusterID, AddSceneCommandID, putAddScene(0, 1, "", 1))
	for _, h := range ep.removed {
		h(1)
	}
	if n := unsignedOf(sceneInfo(t, ep)[0]); n != 0 {
		t.Fatalf("SceneCount = %d after the fabric was removed", n)
	}
}
