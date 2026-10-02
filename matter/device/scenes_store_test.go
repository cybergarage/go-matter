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

package device

import (
	"sync/atomic"
	"testing"

	"github.com/cybergarage/go-matter/matter/cluster/generalcommissioning"
	"github.com/cybergarage/go-matter/matter/protocol/im"
	"github.com/cybergarage/go-matter/matter/store"
)

func sceneIDs(recs []store.SceneRecord) []uint8 {
	ids := make([]uint8, 0, len(recs))
	for _, rec := range recs {
		ids = append(ids, rec.SceneID)
	}
	return ids
}

// TestEndpointScenesPersist checks the scenes an endpoint saves: each
// endpoint loads its own, from the store a restarted device opens; a
// save under the fail-safe lasts only if commissioning completes; and a
// fabric the device is not on saves none.
func TestEndpointScenesPersist(t *testing.T) {
	d, adv, _, _, admin := commissionedDevice(t)
	waitOperational(t, adv, 1)
	fabrics, err := d.store.ListDeviceFabrics()
	if err != nil || len(fabrics) != 1 {
		t.Fatal(fabrics, err)
	}
	fabric := fabrics[0].FabricIndex
	ep1, err := d.AddEndpoint(1, OnOffLightDeviceType)
	if err != nil {
		t.Fatal(err)
	}
	ep2, err := d.AddEndpoint(2, OnOffLightDeviceType)
	if err != nil {
		t.Fatal(err)
	}
	if err := ep1.SaveScenes(fabric, []store.SceneRecord{{SceneID: 1, Name: "Evening"}, {SceneID: 2}}); err != nil {
		t.Fatal(err)
	}
	if err := ep2.SaveScenes(fabric, []store.SceneRecord{{SceneID: 7}}); err != nil {
		t.Fatal(err)
	}
	if err := ep1.SaveScenes(fabric, []store.SceneRecord{{SceneID: 1, Name: "Evening"}}); err != nil {
		t.Fatal(err)
	}
	if recs, _ := d.store.LoadScenes(fabric); len(recs) != 2 {
		t.Fatalf("the store holds %+v, want endpoint 1's scene 1 and endpoint 2's scene 7", recs)
	}

	// A device restarted on the store finds each endpoint's scenes.
	restarted, err := New(WithDeviceStore(d.store), WithPasscode(testPasscode), WithDiscriminator(3840))
	if err != nil {
		t.Fatal(err)
	}
	for id, want := range map[uint16][]uint8{1: {1}, 2: {7}} {
		ep, err := restarted.AddEndpoint(im.EndpointID(id), OnOffLightDeviceType)
		if err != nil {
			t.Fatal(err)
		}
		scenes, err := ep.LoadScenes()
		if err != nil {
			t.Fatal(err)
		}
		if got := sceneIDs(scenes[fabric]); len(got) != len(want) || got[0] != want[0] {
			t.Fatalf("endpoint %d loads scenes %v, want %v", id, got, want)
		}
		if id == 1 && scenes[fabric][0].Name != "Evening" {
			t.Fatalf("endpoint 1 loads %+v, want the scene named Evening", scenes[fabric][0])
		}
	}

	// Under the fail-safe a save is visible, and goes when it expires.
	if err := generalcommissioning.ArmFailSafe(admin, 0, 60, 1); err != nil {
		t.Fatal(err)
	}
	if err := ep1.SaveScenes(fabric, []store.SceneRecord{{SceneID: 1}, {SceneID: 3}}); err != nil {
		t.Fatal(err)
	}
	if scenes, _ := ep1.LoadScenes(); len(scenes[fabric]) != 2 {
		t.Fatalf("endpoint 1 loads %v under the fail-safe, want its 2 scenes", sceneIDs(scenes[fabric]))
	}
	if err := generalcommissioning.ArmFailSafe(admin, 0, 0, 2); err != nil {
		t.Fatal(err)
	}
	if scenes, _ := ep1.LoadScenes(); len(scenes[fabric]) != 1 {
		t.Fatalf("endpoint 1 loads %v after the fail-safe expired, want its 1 scene from before", sceneIDs(scenes[fabric]))
	}

	// A fabric the device is not on keeps no scenes.
	if err := ep1.SaveScenes(fabric+1, []store.SceneRecord{{SceneID: 1}}); err != nil {
		t.Fatal(err)
	}
	if recs, _ := d.store.LoadScenes(fabric + 1); len(recs) != 0 {
		t.Fatalf("the store holds %+v for a fabric the device is not on", recs)
	}
}

// TestRollbackRemovesAddedFabricFromClusters checks that the fail-safe
// rolling back a fabric AddNOC added tells the application clusters, as
// RemoveFabric does, and takes the scenes saved on it.
func TestRollbackRemovesAddedFabricFromClusters(t *testing.T) {
	d, _, pase, _ := startCommissioningWithAdvertiser(t)
	ep, err := d.AddEndpoint(1, OnOffLightDeviceType)
	if err != nil {
		t.Fatal(err)
	}
	var removed atomic.Int32
	ep.HandleFabricRemoved(func(fabric uint8) { removed.Store(int32(fabric)) })
	ca := newTestCA(t, testFabricID)
	addNOCOverPASE(t, pase, ca, testCommissioneeNode)
	fabrics, err := listFabrics(d.opCreds.view())
	if err != nil || len(fabrics) != 1 {
		t.Fatal(fabrics, err)
	}
	fabric := fabrics[0].FabricIndex
	if err := ep.SaveScenes(fabric, []store.SceneRecord{{SceneID: 1}}); err != nil {
		t.Fatal(err)
	}
	if err := generalcommissioning.ArmFailSafe(pase, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the clusters to learn the fabric is gone", func() bool { return removed.Load() == int32(fabric) })
	if recs, _ := d.store.LoadScenes(fabric); len(recs) != 0 {
		t.Fatalf("the store holds %+v of the rolled back fabric", recs)
	}
}
