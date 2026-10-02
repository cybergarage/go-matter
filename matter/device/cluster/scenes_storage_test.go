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
	"maps"
	"sync"
	"testing"

	"github.com/cybergarage/go-matter/matter/protocol/im"
	"github.com/cybergarage/go-matter/matter/store"
)

// sceneStore is a SceneStorage in memory, which outlives the endpoints
// using it as a device's store outlives a restart.
type sceneStore struct {
	mutex  sync.Mutex
	scenes map[uint8][]store.SceneRecord
}

// storingEndpoint is a fakeEndpoint which keeps its scenes in a
// sceneStore.
type storingEndpoint struct {
	*fakeEndpoint
	store *sceneStore
}

func (ep *storingEndpoint) LoadScenes() (map[uint8][]store.SceneRecord, error) {
	ep.store.mutex.Lock()
	defer ep.store.mutex.Unlock()
	return maps.Clone(ep.store.scenes), nil
}

func (ep *storingEndpoint) SaveScenes(fabric uint8, scenes []store.SceneRecord) error {
	ep.store.mutex.Lock()
	defer ep.store.mutex.Unlock()
	if len(scenes) == 0 {
		delete(ep.store.scenes, fabric)
		return nil
	}
	ep.store.scenes[fabric] = scenes
	return nil
}

func (s *sceneStore) stored(fabric uint8) []store.SceneRecord {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.scenes[fabric]
}

// startLight serves an On/Off light with scenes on an endpoint which
// keeps its scenes in st, as a device does from boot.
func startLight(st *sceneStore) (*storingEndpoint, *OnOff, *Scenes) {
	ep := &storingEndpoint{fakeEndpoint: newFakeEndpoint(), store: st}
	light := NewOnOff()
	light.Register(ep)
	scenes := NewScenes()
	scenes.AddSceneHandler(OnOffClusterID, light)
	scenes.Register(ep)
	return ep, light, scenes
}

// TestScenesPersist checks that the scene table outlives a restart: the
// scenes a fabric added and stored are there, by name, transition and
// values, after the light starts again, and a removal lasts too. No scene
// is current after the restart.
func TestScenesPersist(t *testing.T) {
	st := &sceneStore{mutex: sync.Mutex{}, scenes: map[uint8][]store.SceneRecord{}}
	ep, light, _ := startLight(st)
	if s := responseStatus(t, ep.invokeWith(t, ScenesManagementClusterID, AddSceneCommandID, putAddScene(0, 1, "Evening", 1))); s != im.StatusSuccess {
		t.Fatalf("AddScene: status %#x", uint8(s))
	}
	light.Set(false)
	if s := responseStatus(t, ep.invoke(t, ScenesManagementClusterID, StoreSceneCommandID, map[uint8]uint64{0: 0, 1: 2})); s != im.StatusSuccess {
		t.Fatalf("StoreScene: status %#x", uint8(s))
	}
	ep.invokeWith(t, ScenesManagementClusterID, AddSceneCommandID, putAddScene(0, 3, "Gone", 1))
	if s := responseStatus(t, ep.invoke(t, ScenesManagementClusterID, RemoveSceneCommandID, map[uint8]uint64{0: 0, 1: 3})); s != im.StatusSuccess {
		t.Fatalf("RemoveScene: status %#x", uint8(s))
	}
	if n := len(st.stored(1)); n != 2 {
		t.Fatalf("%d scenes stored, want 2", n)
	}

	// The light restarts.
	ep, light, scenes := startLight(st)
	view := responseFields(t, ep.invoke(t, ScenesManagementClusterID, ViewSceneCommandID, map[uint8]uint64{0: 0, 1: 1}))
	if unsignedOf(view[0]) != uint64(im.StatusSuccess) || unsignedOf(view[3]) != 1000 {
		t.Fatalf("ViewScene after the restart = %v", view)
	}
	if name, _ := view[4].UTF8(); name != "Evening" {
		t.Fatalf("ViewScene name after the restart = %q", name)
	}
	if s := responseStatus(t, ep.invoke(t, ScenesManagementClusterID, ViewSceneCommandID, map[uint8]uint64{0: 0, 1: 3})); s != im.StatusNotFound {
		t.Fatalf("ViewScene of the removed scene after the restart: status %#x, want NOT_FOUND", uint8(s))
	}
	info := sceneInfo(t, ep.fakeEndpoint)
	if unsignedOf(info[0]) != 2 {
		t.Fatalf("SceneCount after the restart = %d, want 2", unsignedOf(info[0]))
	}
	if valid, _ := info[3].Bool(); valid {
		t.Fatal("a scene is valid right after the restart")
	}
	ep.invoke(t, ScenesManagementClusterID, RecallSceneCommandID, map[uint8]uint64{0: 0, 1: 1})
	if !light.On() {
		t.Fatal("recalling the restored added scene did not turn the light on")
	}
	ep.invoke(t, ScenesManagementClusterID, RecallSceneCommandID, map[uint8]uint64{0: 0, 1: 2})
	if light.On() {
		t.Fatal("recalling the restored stored scene did not turn the light off")
	}

	// A group's scenes leave the store with the group, and RemoveAllScenes
	// empties it.
	ep.mapped[5] = true
	ep.JoinGroup(1, 5, "")
	ep.invokeWith(t, ScenesManagementClusterID, AddSceneCommandID, putAddScene(5, 1, "", 1))
	if n := len(st.stored(1)); n != 3 {
		t.Fatalf("%d scenes stored, want 3 with the group's", n)
	}
	scenes.RemoveGroups(1, []uint16{5})
	if n := len(st.stored(1)); n != 2 {
		t.Fatalf("%d scenes stored after the group was removed, want 2", n)
	}
	ep.invoke(t, ScenesManagementClusterID, RemoveAllScenesCommandID, map[uint8]uint64{0: 0})
	if n := len(st.stored(1)); n != 0 {
		t.Fatalf("%d scenes stored after RemoveAllScenes, want 0", n)
	}
}
