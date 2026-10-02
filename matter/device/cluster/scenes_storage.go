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
	"cmp"
	"slices"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter/protocol/im"
	"github.com/cybergarage/go-matter/matter/store"
)

// SceneStorage keeps the scene table of a Scenes Management cluster
// across restarts (Matter Application Cluster 1.4.7.1: the scene table is
// persisted); *device.Endpoint is one, which saves it in the device's
// store. On an endpoint which is not, scenes are kept in memory.
type SceneStorage interface {
	// LoadScenes returns the scenes each fabric stored, by fabric index.
	LoadScenes() (map[uint8][]store.SceneRecord, error)
	// SaveScenes replaces the scenes a fabric stored.
	SaveScenes(fabricIndex uint8, scenes []store.SceneRecord) error
}

// loadLocked restores the scene table from storage. The current scenes
// are not restored: after a restart no scene is valid (1.4.8.2).
func (c *Scenes) loadLocked() {
	if c.storage == nil {
		return
	}
	stored, err := c.storage.LoadScenes()
	if err != nil {
		log.Errorf("scenes: load the scene table: %v", err)
		return
	}
	for fabric, recs := range stored {
		for _, rec := range recs {
			if rec.SceneID > maxSceneID || len(rec.Name) > maxSceneNameLength || rec.TransitionMs > maxSceneTransitionMs {
				log.Warnf("scenes: skip stored scene %d of group 0x%04X on fabric %d: out of range", rec.SceneID, rec.GroupID, fabric)
				continue
			}
			if c.remainingCapacityLocked(fabric) == 0 {
				log.Warnf("scenes: skip stored scene %d of group 0x%04X on fabric %d: the table is full", rec.SceneID, rec.GroupID, fabric)
				continue
			}
			c.table[sceneKey{fabric: fabric, group: rec.GroupID, scene: rec.SceneID}] = sceneEntryFromRecord(rec)
		}
	}
}

// save writes a fabric's scenes to storage after a change. A failure is
// logged; the scenes stay as changed in memory.
func (c *Scenes) save(fabric uint8) {
	// Saves follow one another in the order of the changes they write.
	c.saveMutex.Lock()
	defer c.saveMutex.Unlock()
	c.mutex.Lock()
	storage := c.storage
	var recs []store.SceneRecord
	for key, entry := range c.table {
		if key.fabric == fabric {
			recs = append(recs, sceneRecord(key, entry))
		}
	}
	c.mutex.Unlock()
	if storage == nil {
		return
	}
	slices.SortFunc(recs, func(a, b store.SceneRecord) int {
		return cmp.Or(cmp.Compare(a.GroupID, b.GroupID), cmp.Compare(a.SceneID, b.SceneID))
	})
	if err := storage.SaveScenes(fabric, recs); err != nil {
		log.Errorf("scenes: save the scenes of fabric %d: %v", fabric, err)
	}
}

func sceneRecord(key sceneKey, entry sceneEntry) store.SceneRecord {
	rec := store.SceneRecord{
		Endpoint:     0,
		GroupID:      key.group,
		SceneID:      key.scene,
		Name:         entry.name,
		TransitionMs: entry.transition,
		Extensions:   make([]store.SceneExtensionRecord, 0, len(entry.extensions)),
	}
	for _, ext := range entry.extensions {
		values := make([]store.SceneAttributeValueRecord, 0, len(ext.values))
		for _, v := range ext.values {
			values = append(values, store.SceneAttributeValueRecord{Attribute: uint32(v.Attribute), Value: v.Value, Signed: v.Signed, Bits: v.Bits})
		}
		rec.Extensions = append(rec.Extensions, store.SceneExtensionRecord{Cluster: uint32(ext.cluster), Values: values})
	}
	return rec
}

func sceneEntryFromRecord(rec store.SceneRecord) sceneEntry {
	entry := sceneEntry{name: rec.Name, transition: rec.TransitionMs, extensions: make([]sceneExtension, 0, len(rec.Extensions))}
	for _, ext := range rec.Extensions {
		values := make([]SceneAttributeValue, 0, len(ext.Values))
		for _, v := range ext.Values {
			values = append(values, SceneAttributeValue{Attribute: im.AttributeID(v.Attribute), Value: v.Value, Signed: v.Signed, Bits: v.Bits})
		}
		entry.extensions = append(entry.extensions, sceneExtension{cluster: im.ClusterID(ext.Cluster), values: values})
	}
	return entry
}
