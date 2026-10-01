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
	"slices"
	"sync"
	"time"

	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	"github.com/cybergarage/go-matter/matter/protocol/im"
)

// Scenes Management cluster (Matter Application Cluster 1.4).
const (
	ScenesManagementClusterID im.ClusterID = 0x0062

	SceneTableSizeAttributeID  im.AttributeID = 0x0001
	FabricSceneInfoAttributeID im.AttributeID = 0x0002

	AddSceneCommandID           im.CommandID = 0x00
	ViewSceneCommandID          im.CommandID = 0x01
	RemoveSceneCommandID        im.CommandID = 0x02
	RemoveAllScenesCommandID    im.CommandID = 0x03
	StoreSceneCommandID         im.CommandID = 0x04
	RecallSceneCommandID        im.CommandID = 0x05
	GetSceneMembershipCommandID im.CommandID = 0x06

	// ScenesFeatureSceneNames is the SceneNames feature (SN): scenes
	// keep the names AddScene gives them.
	ScenesFeatureSceneNames uint32 = 0x01

	scenesClusterRevision = 1

	// sceneTableSize is how many scenes the endpoint holds, and
	// scenesPerFabric how many of them one fabric may use, so that
	// another fabric always finds room.
	sceneTableSize  = 16
	scenesPerFabric = (sceneTableSize - 1) / 2

	maxSceneID           = 0xFE
	maxSceneNameLength   = 16
	maxSceneTransitionMs = 60_000_000

	fabricIndexTag = 0xFE
)

// SceneAttributeValue is the value of one attribute a scene sets, an
// AttributeValuePairStruct: an unsigned or signed integer of
// Bits bits.
type SceneAttributeValue struct {
	Attribute im.AttributeID
	Value     uint64
	Signed    bool
	Bits      int
}

// SceneHandler is a cluster with attributes scenes store and recall,
// such as On/Off with its OnOff attribute.
type SceneHandler interface {
	// SceneValues returns the current values of the attributes a scene
	// stores, for StoreScene.
	SceneValues() []SceneAttributeValue
	// RecallScene sets the attributes to values over transition.
	RecallScene(values []SceneAttributeValue, transition time.Duration)
}

// sceneInvalidating is a SceneHandler which tells the scenes when its
// attributes change other than by a recall, which leaves the current
// scene no longer valid.
type sceneInvalidating interface {
	setSceneInvalidator(invalidate func())
}

// FabricEndpoint is an Endpoint which tells the fabric a session accesses
// it on, for fabric-scoped clusters; *device.Endpoint is one.
type FabricEndpoint interface {
	Endpoint
	HandleAttributeRead(cluster im.ClusterID, attribute im.AttributeID, h im.AttributeReadHandler, opts ...im.HandlerOption)
	AccessingFabric(sess im.SecureSession) uint8
	HandleFabricRemoved(h func(fabricIndex uint8))
}

type sceneKey struct {
	fabric uint8
	group  uint16
	scene  uint8
}

type sceneExtension struct {
	cluster im.ClusterID
	values  []SceneAttributeValue
}

type sceneEntry struct {
	name       string
	transition uint32
	extensions []sceneExtension
}

// fabricScene is a fabric's current scene.
type fabricScene struct {
	group uint16
	scene uint8
	valid bool
}

// Scenes is the server of the Scenes Management cluster with the
// SceneNames feature: each fabric stores the attribute values of the
// endpoint's scene handlers as scenes, and recalls them. Scenes are
// stored in group 0 only, since the endpoint belongs to no group, and
// they are kept in memory.
type Scenes struct {
	mutex    sync.Mutex
	endpoint FabricEndpoint
	handlers map[im.ClusterID]SceneHandler
	table    map[sceneKey]sceneEntry
	current  map[uint8]fabricScene
	// recalling is set while a recall sets attributes, which leaves the
	// recalled scene valid.
	recalling bool
}

// NewScenes returns a Scenes Management cluster server.
func NewScenes() *Scenes {
	return &Scenes{
		mutex:     sync.Mutex{},
		endpoint:  nil,
		handlers:  map[im.ClusterID]SceneHandler{},
		table:     map[sceneKey]sceneEntry{},
		current:   map[uint8]fabricScene{},
		recalling: false,
	}
}

// AddSceneHandler makes the attributes of a cluster on the endpoint part
// of the scenes.
func (c *Scenes) AddSceneHandler(cluster im.ClusterID, h SceneHandler) {
	c.mutex.Lock()
	c.handlers[cluster] = h
	c.mutex.Unlock()
	if inv, ok := h.(sceneInvalidating); ok {
		inv.setSceneInvalidator(c.invalidate)
	}
}

// invalidate marks every fabric's current scene invalid, unless a recall
// is setting the attributes.
func (c *Scenes) invalidate() {
	c.mutex.Lock()
	if c.recalling {
		c.mutex.Unlock()
		return
	}
	changed := false
	for fabric, cur := range c.current {
		if cur.valid {
			cur.valid = false
			c.current[fabric] = cur
			changed = true
		}
	}
	ep := c.endpoint
	c.mutex.Unlock()
	if changed && ep != nil {
		ep.NotifyAttributeChanged(ScenesManagementClusterID, FabricSceneInfoAttributeID)
	}
}

// Register serves the cluster on ep.
func (c *Scenes) Register(ep FabricEndpoint) {
	c.mutex.Lock()
	c.endpoint = ep
	c.mutex.Unlock()

	ep.HandleAttribute(ScenesManagementClusterID, SceneTableSizeAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		enc.PutUnsigned2(tag, sceneTableSize)
		return im.StatusSuccess
	})
	ep.HandleAttributeRead(ScenesManagementClusterID, FabricSceneInfoAttributeID, c.readFabricSceneInfo)
	ep.HandleAttribute(ScenesManagementClusterID, featureMapAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		enc.PutUnsigned4(tag, ScenesFeatureSceneNames)
		return im.StatusSuccess
	})
	ep.HandleAttribute(ScenesManagementClusterID, clusterRevisionAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		enc.PutUnsigned2(tag, scenesClusterRevision)
		return im.StatusSuccess
	})

	manage := im.WithPrivilege(im.PrivilegeManage)
	ep.HandleCommand(ScenesManagementClusterID, AddSceneCommandID, c.addScene, manage, im.WithResponseCommand(AddSceneCommandID))
	ep.HandleCommand(ScenesManagementClusterID, ViewSceneCommandID, c.viewScene, im.WithResponseCommand(ViewSceneCommandID))
	ep.HandleCommand(ScenesManagementClusterID, RemoveSceneCommandID, c.removeScene, manage, im.WithResponseCommand(RemoveSceneCommandID))
	ep.HandleCommand(ScenesManagementClusterID, RemoveAllScenesCommandID, c.removeAllScenes, manage, im.WithResponseCommand(RemoveAllScenesCommandID))
	ep.HandleCommand(ScenesManagementClusterID, StoreSceneCommandID, c.storeScene, manage, im.WithResponseCommand(StoreSceneCommandID))
	ep.HandleCommand(ScenesManagementClusterID, RecallSceneCommandID, c.recallScene)
	ep.HandleCommand(ScenesManagementClusterID, GetSceneMembershipCommandID, c.getSceneMembership, im.WithResponseCommand(GetSceneMembershipCommandID))
	ep.HandleFabricRemoved(c.removeFabric)
}

// removeFabric removes the scenes of a removed fabric.
func (c *Scenes) removeFabric(fabric uint8) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	for key := range c.table {
		if key.fabric == fabric {
			delete(c.table, key)
		}
	}
	delete(c.current, fabric)
}

// countLocked returns how many scenes a fabric stores.
func (c *Scenes) countLocked(fabric uint8) int {
	n := 0
	for key := range c.table {
		if key.fabric == fabric {
			n++
		}
	}
	return n
}

// remainingCapacityLocked returns how many more scenes a fabric can
// store.
func (c *Scenes) remainingCapacityLocked(fabric uint8) int {
	return max(0, min(scenesPerFabric-c.countLocked(fabric), sceneTableSize-len(c.table)))
}

// readFabricSceneInfo reports, for the accessing fabric and every fabric
// with scenes, its scene count and remaining capacity, and to the
// accessing fabric its current scene.
func (c *Scenes) readFabricSceneInfo(req *im.AttributeRequest, enc tlv.Encoder, tag tlv.Tag) im.Status {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	accessing := c.endpoint.AccessingFabric(req.Session)
	var fabrics []uint8
	if accessing != 0 {
		fabrics = append(fabrics, accessing)
	}
	if !req.FabricFiltered {
		for key := range c.table {
			if !slices.Contains(fabrics, key.fabric) {
				fabrics = append(fabrics, key.fabric)
			}
		}
	}
	slices.Sort(fabrics)
	enc.BeginArray(tag)
	for _, fabric := range fabrics {
		enc.BeginStructure(tlv.NewAnonymousTag())
		enc.PutUnsigned1(tlv.NewContextTag(0), uint8(c.countLocked(fabric))) // nolint: gosec // at most the table size
		if fabric == accessing {
			cur := c.current[fabric]
			enc.PutUnsigned1(tlv.NewContextTag(1), cur.scene)
			enc.PutUnsigned2(tlv.NewContextTag(2), cur.group)
			enc.PutBool(tlv.NewContextTag(3), cur.valid)
		}
		enc.PutUnsigned1(tlv.NewContextTag(4), uint8(c.remainingCapacityLocked(fabric))) // nolint: gosec // at most the table size
		enc.PutUnsigned1(tlv.NewContextTag(fabricIndexTag), fabric)
		if err := enc.EndContainer(); err != nil {
			return im.StatusFailure
		}
	}
	if err := enc.EndContainer(); err != nil {
		return im.StatusFailure
	}
	return im.StatusSuccess
}

// sceneTarget reads the GroupID and SceneID of a command, and checks them
// and the accessing fabric: a scene command acts for the accessing
// fabric, in a group the endpoint belongs to, which is only group 0.
func (c *Scenes) sceneTarget(req *im.CommandRequest, withScene bool) (sceneKey, im.Status) {
	key := sceneKey{fabric: c.endpoint.AccessingFabric(req.Session), group: 0, scene: 0}
	group, ok := unsignedField(req, 0)
	if !ok || 0xFFFF < group {
		return key, im.StatusInvalidCommand
	}
	key.group = uint16(group)
	if withScene {
		scene, ok := unsignedField(req, 1)
		if !ok || 0xFF < scene {
			return key, im.StatusInvalidCommand
		}
		key.scene = uint8(scene)
		if maxSceneID < scene {
			return key, im.StatusConstraintError
		}
	}
	if key.fabric == 0 {
		return key, im.StatusUnsupportedAccess
	}
	if key.group != 0 {
		return key, im.StatusInvalidCommand
	}
	return key, im.StatusSuccess
}

// sceneResponse encodes the {Status, GroupID[, SceneID]} fields of a
// scene response command, and more fields after them.
func sceneResponse(cmd im.CommandID, status im.Status, key sceneKey, withScene bool, more func(enc tlv.Encoder) error) im.CommandResult {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewContextTag(1))
	enc.PutUnsigned1(tlv.NewContextTag(0), uint8(status))
	enc.PutUnsigned2(tlv.NewContextTag(1), key.group)
	if withScene {
		enc.PutUnsigned1(tlv.NewContextTag(2), key.scene)
	}
	if more != nil {
		if err := more(enc); err != nil {
			return im.CommandStatus(im.StatusFailure)
		}
	}
	if err := enc.EndContainer(); err != nil {
		return im.CommandStatus(im.StatusFailure)
	}
	return im.CommandResponse(cmd, enc.Bytes())
}

// addScene handles AddScene.
func (c *Scenes) addScene(req *im.CommandRequest) im.CommandResult {
	key, status := c.sceneTarget(req, true)
	if status == im.StatusInvalidCommand && !hasSceneFields(req) {
		return im.CommandStatus(status)
	}
	entry := sceneEntry{name: "", transition: 0, extensions: nil}
	if status == im.StatusSuccess {
		entry, status = decodeAddScene(req)
	}
	if status != im.StatusSuccess {
		return sceneResponse(AddSceneCommandID, status, key, true, nil)
	}

	c.mutex.Lock()
	// Only the extensions of the endpoint's clusters are kept.
	entry.extensions = slices.DeleteFunc(entry.extensions, func(e sceneExtension) bool {
		_, ok := c.handlers[e.cluster]
		return !ok
	})
	_, exists := c.table[key]
	if !exists && c.remainingCapacityLocked(key.fabric) == 0 {
		c.mutex.Unlock()
		return sceneResponse(AddSceneCommandID, im.StatusResourceExhausted, key, true, nil)
	}
	c.table[key] = entry
	if cur, ok := c.current[key.fabric]; ok && cur.group == key.group && cur.scene == key.scene {
		cur.valid = false
		c.current[key.fabric] = cur
	}
	c.mutex.Unlock()
	c.endpoint.NotifyAttributeChanged(ScenesManagementClusterID, FabricSceneInfoAttributeID)
	return sceneResponse(AddSceneCommandID, im.StatusSuccess, key, true, nil)
}

func hasSceneFields(req *im.CommandRequest) bool {
	_, ok1 := unsignedField(req, 0)
	_, ok2 := unsignedField(req, 1)
	return ok1 && ok2
}

// decodeAddScene decodes the TransitionTime, SceneName and
// ExtensionFieldSetStructs of an AddScene.
func decodeAddScene(req *im.CommandRequest) (sceneEntry, im.Status) {
	entry := sceneEntry{name: "", transition: 0, extensions: nil}
	transition, ok := unsignedField(req, 2)
	if !ok {
		return entry, im.StatusInvalidCommand
	}
	if maxSceneTransitionMs < transition {
		return entry, im.StatusConstraintError
	}
	entry.transition = uint32(transition)
	if field, ok := req.Field(3); ok {
		name, ok := field.UTF8()
		if !ok {
			return entry, im.StatusInvalidCommand
		}
		if maxSceneNameLength < len(name) {
			return entry, im.StatusConstraintError
		}
		entry.name = name
	}
	dec, err := req.Decoder()
	if err != nil {
		return entry, im.StatusInvalidCommand
	}
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			break
		}
		tag, _ := contextTag(elem)
		switch {
		case tag == 4 && elem.Type().IsArray():
			for dec.Next() {
				item := dec.Element()
				if item.Type().IsEndOfContainer() {
					break
				}
				if !item.Type().IsStructure() {
					return entry, im.StatusInvalidCommand
				}
				ext, status := decodeExtensionFieldSet(dec)
				if status != im.StatusSuccess {
					return entry, status
				}
				entry.extensions = append(entry.extensions, ext)
			}
		case elem.Type().IsContainer():
			if err := skipContainer(dec); err != nil {
				return entry, im.StatusInvalidCommand
			}
		}
	}
	if dec.Error() != nil {
		return entry, im.StatusInvalidCommand
	}
	return entry, im.StatusSuccess
}

// decodeExtensionFieldSet decodes the ExtensionFieldSetStruct dec has
// just entered.
func decodeExtensionFieldSet(dec tlv.Decoder) (sceneExtension, im.Status) {
	ext := sceneExtension{cluster: 0, values: nil}
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			return ext, im.StatusSuccess
		}
		tag, _ := contextTag(elem)
		switch {
		case tag == 0 && !elem.Type().IsContainer():
			v, ok := elem.Unsigned()
			if !ok || 0xFFFFFFFF < v {
				return ext, im.StatusInvalidCommand
			}
			ext.cluster = im.ClusterID(v)
		case tag == 1 && elem.Type().IsArray():
			for dec.Next() {
				item := dec.Element()
				if item.Type().IsEndOfContainer() {
					break
				}
				if !item.Type().IsStructure() {
					return ext, im.StatusInvalidCommand
				}
				value, status := decodeAttributeValuePair(dec)
				if status != im.StatusSuccess {
					return ext, status
				}
				ext.values = append(ext.values, value)
			}
		case elem.Type().IsContainer():
			if err := skipContainer(dec); err != nil {
				return ext, im.StatusInvalidCommand
			}
		}
	}
	return ext, im.StatusInvalidCommand
}

// attributeValueTags are the AttributeValuePairStruct fields of each
// value type, from ValueUnsigned8 to ValueSigned64.
var attributeValueTags = []struct {
	signed bool
	bits   int
}{{false, 8}, {true, 8}, {false, 16}, {true, 16}, {false, 32}, {true, 32}, {false, 64}, {true, 64}}

// decodeAttributeValuePair decodes the AttributeValuePairStruct dec has
// just entered: its AttributeID and its one value field.
func decodeAttributeValuePair(dec tlv.Decoder) (SceneAttributeValue, im.Status) {
	value := SceneAttributeValue{Attribute: 0, Value: 0, Signed: false, Bits: 0}
	hasAttribute := false
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			if !hasAttribute || value.Bits == 0 {
				return value, im.StatusInvalidCommand
			}
			return value, im.StatusSuccess
		}
		tag, _ := contextTag(elem)
		switch {
		case tag == 0:
			v, ok := elem.Unsigned()
			if !ok || 0xFFFFFFFF < v {
				return value, im.StatusInvalidCommand
			}
			value.Attribute = im.AttributeID(v)
			hasAttribute = true
		case 1 <= tag && int(tag) <= len(attributeValueTags):
			kind := attributeValueTags[tag-1]
			value.Signed, value.Bits = kind.signed, kind.bits
			if kind.signed {
				v, ok := elem.Signed()
				if !ok {
					return value, im.StatusInvalidCommand
				}
				value.Value = uint64(v) // nolint: gosec // kept as its bits
			} else {
				v, ok := elem.Unsigned()
				if !ok {
					return value, im.StatusInvalidCommand
				}
				value.Value = v
			}
		case elem.Type().IsContainer():
			if err := skipContainer(dec); err != nil {
				return value, im.StatusInvalidCommand
			}
		}
	}
	return value, im.StatusInvalidCommand
}

// encodeExtensionFieldSets encodes a scene's extensions as the
// ExtensionFieldSetStructs field with tag.
func encodeExtensionFieldSets(enc tlv.Encoder, tag tlv.Tag, extensions []sceneExtension) error {
	enc.BeginArray(tag)
	for _, ext := range extensions {
		enc.BeginStructure(tlv.NewAnonymousTag())
		enc.PutUnsigned4(tlv.NewContextTag(0), uint32(ext.cluster))
		enc.BeginArray(tlv.NewContextTag(1))
		for _, v := range ext.values {
			enc.BeginStructure(tlv.NewAnonymousTag())
			enc.PutUnsigned4(tlv.NewContextTag(0), uint32(v.Attribute))
			valueTag := tlv.NewContextTag(valueTagOf(v))
			if v.Signed {
				if err := enc.PutSigned(valueTag, int64(v.Value)); err != nil { // nolint: gosec // kept as its bits
					return err
				}
			} else if err := enc.PutUnsigned(valueTag, v.Value); err != nil {
				return err
			}
			if err := enc.EndContainer(); err != nil {
				return err
			}
		}
		if err := enc.EndContainer(); err != nil {
			return err
		}
		if err := enc.EndContainer(); err != nil {
			return err
		}
	}
	return enc.EndContainer()
}

func valueTagOf(v SceneAttributeValue) uint8 {
	for i, kind := range attributeValueTags {
		if kind.signed == v.Signed && kind.bits == v.Bits {
			return uint8(i + 1) // nolint: gosec // 1 to 8
		}
	}
	return 7 // ValueUnsigned64
}

// viewScene handles ViewScene.
func (c *Scenes) viewScene(req *im.CommandRequest) im.CommandResult {
	key, status := c.sceneTarget(req, true)
	if status == im.StatusInvalidCommand && !hasSceneFields(req) {
		return im.CommandStatus(status)
	}
	if status != im.StatusSuccess {
		return sceneResponse(ViewSceneCommandID, status, key, true, nil)
	}
	c.mutex.Lock()
	entry, ok := c.table[key]
	c.mutex.Unlock()
	if !ok {
		return sceneResponse(ViewSceneCommandID, im.StatusNotFound, key, true, nil)
	}
	return sceneResponse(ViewSceneCommandID, im.StatusSuccess, key, true, func(enc tlv.Encoder) error {
		enc.PutUnsigned4(tlv.NewContextTag(3), entry.transition)
		if err := enc.PutUTF8(tlv.NewContextTag(4), entry.name); err != nil {
			return err
		}
		return encodeExtensionFieldSets(enc, tlv.NewContextTag(5), entry.extensions)
	})
}

// removeScene handles RemoveScene.
func (c *Scenes) removeScene(req *im.CommandRequest) im.CommandResult {
	key, status := c.sceneTarget(req, true)
	if status == im.StatusInvalidCommand && !hasSceneFields(req) {
		return im.CommandStatus(status)
	}
	if status == im.StatusSuccess {
		c.mutex.Lock()
		if _, ok := c.table[key]; ok {
			delete(c.table, key)
			if cur, ok := c.current[key.fabric]; ok && cur.group == key.group && cur.scene == key.scene {
				cur.valid = false
				c.current[key.fabric] = cur
			}
		} else {
			status = im.StatusNotFound
		}
		c.mutex.Unlock()
		if status == im.StatusSuccess {
			c.endpoint.NotifyAttributeChanged(ScenesManagementClusterID, FabricSceneInfoAttributeID)
		}
	}
	return sceneResponse(RemoveSceneCommandID, status, key, true, nil)
}

// removeAllScenes handles RemoveAllScenes.
func (c *Scenes) removeAllScenes(req *im.CommandRequest) im.CommandResult {
	key, status := c.sceneTarget(req, false)
	if _, ok := unsignedField(req, 0); !ok {
		return im.CommandStatus(im.StatusInvalidCommand)
	}
	if status == im.StatusSuccess {
		c.mutex.Lock()
		for k := range c.table {
			if k.fabric == key.fabric && k.group == key.group {
				delete(c.table, k)
			}
		}
		if cur, ok := c.current[key.fabric]; ok && cur.group == key.group {
			cur.valid = false
			c.current[key.fabric] = cur
		}
		c.mutex.Unlock()
		c.endpoint.NotifyAttributeChanged(ScenesManagementClusterID, FabricSceneInfoAttributeID)
	}
	return sceneResponse(RemoveAllScenesCommandID, status, key, false, nil)
}

// storeScene handles StoreScene: it stores the current values
// of the scene handlers' attributes, keeping the name and transition time
// of a scene it replaces, and makes the scene the current one.
func (c *Scenes) storeScene(req *im.CommandRequest) im.CommandResult {
	key, status := c.sceneTarget(req, true)
	if status == im.StatusInvalidCommand && !hasSceneFields(req) {
		return im.CommandStatus(status)
	}
	if status != im.StatusSuccess {
		return sceneResponse(StoreSceneCommandID, status, key, true, nil)
	}
	c.mutex.Lock()
	entry, exists := c.table[key]
	if !exists && c.remainingCapacityLocked(key.fabric) == 0 {
		c.mutex.Unlock()
		return sceneResponse(StoreSceneCommandID, im.StatusResourceExhausted, key, true, nil)
	}
	handlers := c.sortedHandlersLocked()
	c.mutex.Unlock()

	entry.extensions = nil
	for _, h := range handlers {
		entry.extensions = append(entry.extensions, sceneExtension{cluster: h.cluster, values: h.handler.SceneValues()})
	}
	c.mutex.Lock()
	c.table[key] = entry
	c.current[key.fabric] = fabricScene{group: key.group, scene: key.scene, valid: true}
	c.mutex.Unlock()
	c.endpoint.NotifyAttributeChanged(ScenesManagementClusterID, FabricSceneInfoAttributeID)
	return sceneResponse(StoreSceneCommandID, im.StatusSuccess, key, true, nil)
}

type clusterHandler struct {
	cluster im.ClusterID
	handler SceneHandler
}

func (c *Scenes) sortedHandlersLocked() []clusterHandler {
	handlers := make([]clusterHandler, 0, len(c.handlers))
	for cluster, h := range c.handlers {
		handlers = append(handlers, clusterHandler{cluster: cluster, handler: h})
	}
	slices.SortFunc(handlers, func(a, b clusterHandler) int { return int(a.cluster) - int(b.cluster) })
	return handlers
}

// recallScene handles RecallScene: it sets the attributes the
// scene stores, over the TransitionTime the command gives or else the
// scene's, and makes the scene the current one.
func (c *Scenes) recallScene(req *im.CommandRequest) im.CommandResult {
	key, status := c.sceneTarget(req, true)
	if status != im.StatusSuccess {
		return im.CommandStatus(status)
	}
	c.mutex.Lock()
	entry, ok := c.table[key]
	if !ok {
		c.mutex.Unlock()
		return im.CommandStatus(im.StatusNotFound)
	}
	transition := time.Duration(entry.transition) * time.Millisecond
	if field, ok := req.Field(2); ok && !field.Type().IsNull() {
		v, ok := field.Unsigned()
		if !ok {
			c.mutex.Unlock()
			return im.CommandStatus(im.StatusInvalidCommand)
		}
		if maxSceneTransitionMs < v {
			c.mutex.Unlock()
			return im.CommandStatus(im.StatusConstraintError)
		}
		transition = time.Duration(v) * time.Millisecond // nolint: gosec // bounded above
	}
	c.recalling = true
	handlers := make(map[im.ClusterID]SceneHandler, len(c.handlers))
	maps.Copy(handlers, c.handlers)
	c.mutex.Unlock()

	for _, ext := range entry.extensions {
		if h, ok := handlers[ext.cluster]; ok {
			h.RecallScene(ext.values, transition)
		}
	}

	c.mutex.Lock()
	c.recalling = false
	c.current[key.fabric] = fabricScene{group: key.group, scene: key.scene, valid: true}
	c.mutex.Unlock()
	c.endpoint.NotifyAttributeChanged(ScenesManagementClusterID, FabricSceneInfoAttributeID)
	return im.CommandStatus(im.StatusSuccess)
}

// getSceneMembership handles GetSceneMembership: the scenes
// of a group, and how many more the fabric can store.
func (c *Scenes) getSceneMembership(req *im.CommandRequest) im.CommandResult {
	key, status := c.sceneTarget(req, false)
	if _, ok := unsignedField(req, 0); !ok {
		return im.CommandStatus(im.StatusInvalidCommand)
	}
	c.mutex.Lock()
	capacity := c.remainingCapacityLocked(key.fabric)
	var scenes []uint8
	for k := range c.table {
		if k.fabric == key.fabric && k.group == key.group {
			scenes = append(scenes, k.scene)
		}
	}
	c.mutex.Unlock()
	slices.Sort(scenes)
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewContextTag(1))
	enc.PutUnsigned1(tlv.NewContextTag(0), uint8(status))
	if status == im.StatusUnsupportedAccess {
		enc.PutNull(tlv.NewContextTag(1))
	} else {
		enc.PutUnsigned1(tlv.NewContextTag(1), uint8(capacity)) // nolint: gosec // at most the table size
	}
	enc.PutUnsigned2(tlv.NewContextTag(2), key.group)
	if status == im.StatusSuccess {
		enc.BeginArray(tlv.NewContextTag(3))
		for _, s := range scenes {
			enc.PutUnsigned1(tlv.NewAnonymousTag(), s)
		}
		if err := enc.EndContainer(); err != nil {
			return im.CommandStatus(im.StatusFailure)
		}
	}
	if err := enc.EndContainer(); err != nil {
		return im.CommandStatus(im.StatusFailure)
	}
	return im.CommandResponse(GetSceneMembershipCommandID, enc.Bytes())
}

func contextTag(elem tlv.Element) (uint8, bool) {
	ct, ok := elem.Tag().(tlv.ContextTag)
	if !ok {
		return 0, false
	}
	return uint8(ct.ContextNumber()), true
}

// skipContainer skips the rest of the container dec has just entered.
func skipContainer(dec tlv.Decoder) error {
	depth := 1
	for depth > 0 && dec.Next() {
		elem := dec.Element()
		switch {
		case elem.Type().IsEndOfContainer():
			depth--
		case elem.Type().IsContainer():
			depth++
		}
	}
	return dec.Error()
}
