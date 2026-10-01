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
	"slices"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	"github.com/cybergarage/go-matter/matter/protocol/im"
	"github.com/cybergarage/go-matter/matter/store"
)

// Group Key Management cluster (Matter Core 11.2).
const (
	GroupKeyManagementClusterID im.ClusterID = 0x003F

	groupKeyMapAttributeID           im.AttributeID = 0x0000
	groupTableAttributeID            im.AttributeID = 0x0001
	maxGroupsPerFabricAttributeID    im.AttributeID = 0x0002
	maxGroupKeysPerFabricAttributeID im.AttributeID = 0x0003

	keySetWriteCommandID                  im.CommandID = 0x00
	keySetReadCommandID                   im.CommandID = 0x01
	keySetReadResponseCommandID           im.CommandID = 0x02
	keySetRemoveCommandID                 im.CommandID = 0x03
	keySetReadAllIndicesCommandID         im.CommandID = 0x04
	keySetReadAllIndicesResponseCommandID im.CommandID = 0x05

	groupKeyManagementClusterRevision = 2

	// MaxGroupsPerFabric is how many groups a fabric may map keys to and
	// put the node's endpoints in, and MaxGroupKeysPerFabric how many key
	// sets it may hold, its IPK included.
	MaxGroupsPerFabric    = 4
	MaxGroupKeysPerFabric = 3

	// MaxGroupNameLength is the longest group name (Groups cluster).
	MaxGroupNameLength = 16

	epochKeyLength = 16
)

// deviceStoreRW is what the clusters write through: the store, or the
// armed fail-safe's transaction.
type deviceStoreRW interface {
	store.DeviceStoreReader
	store.DeviceStoreWriter
}

// writerLocked returns what a change goes through: the fail-safe's
// transaction while it is armed, so that the change lasts only if
// commissioning completes, and the store otherwise.
func (oc *operationalCredentials) writerLocked() deviceStoreRW {
	if tx := oc.armedLocked(); tx != nil {
		return tx
	}
	return oc.store
}

// groupKeyManagement is the server of the Group Key Management cluster:
// each fabric's group key sets, which key set each group uses, and the
// groups the node's endpoints joined, which the Groups cluster of an
// application endpoint changes.
type groupKeyManagement struct {
	oc *operationalCredentials
}

func (gk *groupKeyManagement) register(srv *im.Server) {
	srv.HandleAttributeRead(rootEndpoint, GroupKeyManagementClusterID, groupKeyMapAttributeID, gk.readGroupKeyMap)
	srv.HandleAttributeWrite(rootEndpoint, GroupKeyManagementClusterID, groupKeyMapAttributeID, gk.writeGroupKeyMap, im.WithPrivilege(im.PrivilegeManage))
	srv.HandleAttributeRead(rootEndpoint, GroupKeyManagementClusterID, groupTableAttributeID, gk.readGroupTable)
	for attribute, v := range map[im.AttributeID]uint16{
		maxGroupsPerFabricAttributeID:    MaxGroupsPerFabric,
		maxGroupKeysPerFabricAttributeID: MaxGroupKeysPerFabric,
		clusterRevisionAttributeID:       groupKeyManagementClusterRevision,
	} {
		srv.HandleAttribute(rootEndpoint, GroupKeyManagementClusterID, attribute, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
			enc.PutUnsigned2(tag, v)
			return im.StatusSuccess
		})
	}
	srv.HandleAttribute(rootEndpoint, GroupKeyManagementClusterID, featureMapAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		enc.PutUnsigned4(tag, 0)
		return im.StatusSuccess
	})

	administer := im.WithPrivilege(im.PrivilegeAdminister)
	srv.HandleCommand(rootEndpoint, GroupKeyManagementClusterID, keySetWriteCommandID, gk.keySetWrite, administer)
	srv.HandleCommand(rootEndpoint, GroupKeyManagementClusterID, keySetReadCommandID, gk.keySetRead, administer, im.WithResponseCommand(keySetReadResponseCommandID))
	srv.HandleCommand(rootEndpoint, GroupKeyManagementClusterID, keySetRemoveCommandID, gk.keySetRemove, administer)
	srv.HandleCommand(rootEndpoint, GroupKeyManagementClusterID, keySetReadAllIndicesCommandID, gk.keySetReadAllIndices, administer, im.WithResponseCommand(keySetReadAllIndicesResponseCommandID))
}

// load reads a fabric's group key state as the clusters see it.
func (gk *groupKeyManagement) load(fabricIndex uint8) (store.GroupKeysRecord, error) {
	gk.oc.mutex.Lock()
	defer gk.oc.mutex.Unlock()
	return gk.oc.view().LoadGroupKeys(fabricIndex)
}

// update changes a fabric's group key state with change, which returns the
// status to answer with; the state is saved only on success.
func (gk *groupKeyManagement) update(fabricIndex uint8, change func(rec *store.GroupKeysRecord) im.Status) im.Status {
	gk.oc.mutex.Lock()
	defer gk.oc.mutex.Unlock()
	w := gk.oc.writerLocked()
	rec, err := w.LoadGroupKeys(fabricIndex)
	if err != nil {
		return im.StatusFailure
	}
	if status := change(&rec); status != im.StatusSuccess {
		return status
	}
	if err := w.SaveGroupKeys(fabricIndex, rec); err != nil {
		log.Errorf("device: save the group keys of fabric %d: %v", fabricIndex, err)
		return im.StatusFailure
	}
	return im.StatusSuccess
}

// readGroupKeyMap reports the GroupKeyMap of the fabrics, or of the
// accessing one for a fabric-filtered read.
func (gk *groupKeyManagement) readGroupKeyMap(req *im.AttributeRequest, enc tlv.Encoder, tag tlv.Tag) im.Status {
	fabrics, _, err := gk.oc.scopedFabrics(req)
	if err != nil {
		return im.StatusFailure
	}
	enc.BeginArray(tag)
	for _, f := range fabrics {
		rec, err := gk.load(f.FabricIndex)
		if err != nil {
			return im.StatusFailure
		}
		for _, entry := range rec.KeyMap {
			enc.BeginStructure(tlv.NewAnonymousTag())
			enc.PutUnsigned2(tlv.NewContextTag(1), entry.GroupID)
			enc.PutUnsigned2(tlv.NewContextTag(2), entry.GroupKeySetID)
			enc.PutUnsigned1(tlv.NewContextTag(fabricIndexTag), f.FabricIndex)
			if err := enc.EndContainer(); err != nil {
				return im.StatusFailure
			}
		}
	}
	if err := enc.EndContainer(); err != nil {
		return im.StatusFailure
	}
	return im.StatusSuccess
}

// writeGroupKeyMap replaces, or appends to, the accessing fabric's
// GroupKeyMap: a group is mapped to a key set other than the IPK, once.
func (gk *groupKeyManagement) writeGroupKeyMap(req *im.AttributeWriteRequest) im.Status {
	fabricIndex := gk.oc.accessingFabric(req.Session)
	if fabricIndex == 0 {
		return im.StatusUnsupportedAccess
	}
	dec, elem, err := req.Decoder()
	if err != nil {
		return im.StatusInvalidDataType
	}
	var entries []store.GroupKeyMapEntry
	switch {
	case req.Append && elem.Type().IsStructure():
		entry, status := decodeGroupKeyMapEntry(dec)
		if status != im.StatusSuccess {
			return status
		}
		entries = []store.GroupKeyMapEntry{entry}
	case !req.Append && elem.Type().IsArray():
		entries = []store.GroupKeyMapEntry{}
		for dec.Next() {
			item := dec.Element()
			if item.Type().IsEndOfContainer() {
				break
			}
			if !item.Type().IsStructure() {
				return im.StatusInvalidDataType
			}
			entry, status := decodeGroupKeyMapEntry(dec)
			if status != im.StatusSuccess {
				return status
			}
			entries = append(entries, entry)
		}
	default:
		return im.StatusInvalidDataType
	}
	return gk.update(fabricIndex, func(rec *store.GroupKeysRecord) im.Status {
		if req.Append {
			entries = append(slices.Clone(rec.KeyMap), entries...)
		}
		for i, e := range entries {
			if slices.ContainsFunc(entries[:i], func(prev store.GroupKeyMapEntry) bool {
				return prev.GroupID == e.GroupID && prev.GroupKeySetID == e.GroupKeySetID
			}) {
				return im.StatusConstraintError
			}
		}
		if MaxGroupsPerFabric < len(entries) {
			return im.StatusResourceExhausted
		}
		rec.KeyMap = entries
		return im.StatusSuccess
	})
}

func decodeGroupKeyMapEntry(dec tlv.Decoder) (store.GroupKeyMapEntry, im.Status) {
	entry := store.GroupKeyMapEntry{GroupID: 0, GroupKeySetID: 0}
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			// Group 0 is no group, and key set 0 the IPK, which is
			// never mapped to a group.
			if entry.GroupID == 0 || entry.GroupKeySetID == 0 {
				return entry, im.StatusConstraintError
			}
			return entry, im.StatusSuccess
		}
		v, ok := elem.Unsigned()
		tag, _ := contextTagNumber(elem)
		if !ok || 0xFFFF < v {
			if tag == 1 || tag == 2 {
				return entry, im.StatusInvalidDataType
			}
			continue
		}
		switch tag {
		case 1:
			entry.GroupID = uint16(v)
		case 2:
			entry.GroupKeySetID = uint16(v)
		}
	}
	return entry, im.StatusInvalidDataType
}

// readGroupTable reports the groups the node's endpoints joined.
func (gk *groupKeyManagement) readGroupTable(req *im.AttributeRequest, enc tlv.Encoder, tag tlv.Tag) im.Status {
	fabrics, _, err := gk.oc.scopedFabrics(req)
	if err != nil {
		return im.StatusFailure
	}
	enc.BeginArray(tag)
	for _, f := range fabrics {
		rec, err := gk.load(f.FabricIndex)
		if err != nil {
			return im.StatusFailure
		}
		for _, g := range rec.Groups {
			enc.BeginStructure(tlv.NewAnonymousTag())
			enc.PutUnsigned2(tlv.NewContextTag(1), g.GroupID)
			enc.BeginArray(tlv.NewContextTag(2))
			for _, ep := range g.Endpoints {
				enc.PutUnsigned2(tlv.NewAnonymousTag(), ep)
			}
			if err := enc.EndContainer(); err != nil {
				return im.StatusFailure
			}
			if err := enc.PutUTF8(tlv.NewContextTag(3), g.Name); err != nil {
				return im.StatusFailure
			}
			enc.PutUnsigned1(tlv.NewContextTag(fabricIndexTag), f.FabricIndex)
			if err := enc.EndContainer(); err != nil {
				return im.StatusFailure
			}
		}
	}
	if err := enc.EndContainer(); err != nil {
		return im.StatusFailure
	}
	return im.StatusSuccess
}

// keySetWrite handles KeySetWrite: it adds or replaces one of
// the accessing fabric's key sets, other than the IPK.
func (gk *groupKeyManagement) keySetWrite(req *im.CommandRequest) im.CommandResult {
	fabricIndex := gk.oc.accessingFabric(req.Session)
	if fabricIndex == 0 {
		return im.CommandStatus(im.StatusUnsupportedAccess)
	}
	dec, err := req.Decoder()
	if err != nil {
		return im.CommandStatus(im.StatusInvalidCommand)
	}
	var set store.GroupKeySet
	status := im.StatusInvalidCommand
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			break
		}
		if tag, _ := contextTagNumber(elem); tag == 0 && elem.Type().IsStructure() {
			set, status = decodeGroupKeySet(dec)
		} else if elem.Type().IsContainer() {
			if err := skipTLVContainer(dec); err != nil {
				return im.CommandStatus(im.StatusInvalidCommand)
			}
		}
	}
	if status != im.StatusSuccess {
		return im.CommandStatus(status)
	}
	return im.CommandStatus(gk.update(fabricIndex, func(rec *store.GroupKeysRecord) im.Status {
		i := slices.IndexFunc(rec.KeySets, func(s store.GroupKeySet) bool { return s.GroupKeySetID == set.GroupKeySetID })
		if 0 <= i {
			rec.KeySets[i] = set
			return im.StatusSuccess
		}
		if MaxGroupKeysPerFabric <= len(rec.KeySets) {
			return im.StatusResourceExhausted
		}
		rec.KeySets = append(rec.KeySets, set)
		return im.StatusSuccess
	}))
}

// decodeGroupKeySet decodes the GroupKeySetStruct dec has just entered and
// checks it: not the IPK, TrustFirst, and epoch keys of 16 bytes
// given in order of their start times, the first one at least.
func decodeGroupKeySet(dec tlv.Decoder) (store.GroupKeySet, im.Status) {
	set := store.GroupKeySet{GroupKeySetID: 0, SecurityPolicy: 0, EpochKeys: nil}
	var keys [store.MaxEpochKeys][]byte
	var starts [store.MaxEpochKeys]*uint64
	hasID, hasPolicy := false, false
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			break
		}
		tag, _ := contextTagNumber(elem)
		switch {
		case elem.Type().IsNull():
		case tag == 0:
			v, ok := elem.Unsigned()
			if !ok || 0xFFFF < v {
				return set, im.StatusInvalidCommand
			}
			set.GroupKeySetID, hasID = uint16(v), true
		case tag == 1:
			v, ok := elem.Unsigned()
			if !ok {
				return set, im.StatusInvalidCommand
			}
			if v != uint64(store.GroupKeySecurityPolicyTrustFirst) {
				return set, im.StatusConstraintError
			}
			hasPolicy = true
		case 2 <= tag && tag <= 7:
			i := (tag - 2) / 2
			if tag%2 == 0 {
				key, ok := elem.Bytes()
				if !ok {
					return set, im.StatusInvalidCommand
				}
				if len(key) != epochKeyLength {
					return set, im.StatusConstraintError
				}
				keys[i] = key
			} else {
				v, ok := elem.Unsigned()
				if !ok {
					return set, im.StatusInvalidCommand
				}
				starts[i] = &v
			}
		case elem.Type().IsContainer():
			if err := skipTLVContainer(dec); err != nil {
				return set, im.StatusInvalidCommand
			}
		}
	}
	if !hasID || !hasPolicy || set.GroupKeySetID == 0 {
		return set, im.StatusInvalidCommand
	}
	for i := range store.MaxEpochKeys {
		if keys[i] == nil && starts[i] == nil {
			break
		}
		// A key comes with its start time, after the one before it; the
		// first one starts at a time other than 0.
		if keys[i] == nil || starts[i] == nil {
			return set, im.StatusInvalidCommand
		}
		start := *starts[i]
		if n := len(set.EpochKeys); (n == 0 && start == 0) || (0 < n && start <= set.EpochKeys[n-1].StartTime) {
			return set, im.StatusInvalidCommand
		}
		set.EpochKeys = append(set.EpochKeys, store.EpochKey{Key: keys[i], StartTime: start})
	}
	if len(set.EpochKeys) == 0 {
		return set, im.StatusInvalidCommand
	}
	for i := len(set.EpochKeys); i < store.MaxEpochKeys; i++ {
		if keys[i] != nil || starts[i] != nil {
			return set, im.StatusInvalidCommand
		}
	}
	return set, im.StatusSuccess
}

func keySetIDField(req *im.CommandRequest) (uint16, bool) {
	field, ok := req.Field(0)
	if !ok {
		return 0, false
	}
	v, ok := field.Unsigned()
	if !ok || 0xFFFF < v {
		return 0, false
	}
	return uint16(v), true
}

// keySetRead handles KeySetRead: a key set's policy and start
// times, without its keys.
func (gk *groupKeyManagement) keySetRead(req *im.CommandRequest) im.CommandResult {
	fabricIndex := gk.oc.accessingFabric(req.Session)
	if fabricIndex == 0 {
		return im.CommandStatus(im.StatusUnsupportedAccess)
	}
	id, ok := keySetIDField(req)
	if !ok {
		return im.CommandStatus(im.StatusInvalidCommand)
	}
	rec, err := gk.load(fabricIndex)
	if err != nil {
		return im.CommandStatus(im.StatusFailure)
	}
	i := slices.IndexFunc(rec.KeySets, func(s store.GroupKeySet) bool { return s.GroupKeySetID == id })
	if i < 0 {
		return im.CommandStatus(im.StatusNotFound)
	}
	set := rec.KeySets[i]
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewContextTag(1))
	enc.BeginStructure(tlv.NewContextTag(0))
	enc.PutUnsigned2(tlv.NewContextTag(0), set.GroupKeySetID)
	enc.PutUnsigned1(tlv.NewContextTag(1), uint8(set.SecurityPolicy))
	for k := range store.MaxEpochKeys {
		keyTag := tlv.NewContextTag(uint8(2 + 2*k))   // nolint: gosec // 2 to 6
		startTag := tlv.NewContextTag(uint8(3 + 2*k)) // nolint: gosec // 3 to 7
		enc.PutNull(keyTag)                           // keys are never read back
		if k < len(set.EpochKeys) {
			enc.PutUnsigned8(startTag, set.EpochKeys[k].StartTime)
		} else {
			enc.PutNull(startTag)
		}
	}
	if err := enc.EndContainer(); err != nil {
		return im.CommandStatus(im.StatusFailure)
	}
	if err := enc.EndContainer(); err != nil {
		return im.CommandStatus(im.StatusFailure)
	}
	return im.CommandResponse(keySetReadResponseCommandID, enc.Bytes())
}

// keySetRemove handles KeySetRemove: it removes a key set other
// than the IPK, and the groups mapped to it.
func (gk *groupKeyManagement) keySetRemove(req *im.CommandRequest) im.CommandResult {
	fabricIndex := gk.oc.accessingFabric(req.Session)
	if fabricIndex == 0 {
		return im.CommandStatus(im.StatusUnsupportedAccess)
	}
	id, ok := keySetIDField(req)
	if !ok || id == 0 {
		return im.CommandStatus(im.StatusInvalidCommand)
	}
	return im.CommandStatus(gk.update(fabricIndex, func(rec *store.GroupKeysRecord) im.Status {
		i := slices.IndexFunc(rec.KeySets, func(s store.GroupKeySet) bool { return s.GroupKeySetID == id })
		if i < 0 {
			return im.StatusNotFound
		}
		rec.KeySets = slices.Delete(rec.KeySets, i, i+1)
		rec.KeyMap = slices.DeleteFunc(rec.KeyMap, func(e store.GroupKeyMapEntry) bool { return e.GroupKeySetID == id })
		return im.StatusSuccess
	}))
}

// keySetReadAllIndices handles KeySetReadAllIndices: the IDs of
// the accessing fabric's key sets, the IPK's included.
func (gk *groupKeyManagement) keySetReadAllIndices(req *im.CommandRequest) im.CommandResult {
	fabricIndex := gk.oc.accessingFabric(req.Session)
	if fabricIndex == 0 {
		return im.CommandStatus(im.StatusUnsupportedAccess)
	}
	rec, err := gk.load(fabricIndex)
	if err != nil {
		return im.CommandStatus(im.StatusFailure)
	}
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewContextTag(1))
	enc.BeginArray(tlv.NewContextTag(0))
	for _, set := range rec.KeySets {
		enc.PutUnsigned2(tlv.NewAnonymousTag(), set.GroupKeySetID)
	}
	if err := enc.EndContainer(); err != nil {
		return im.CommandStatus(im.StatusFailure)
	}
	if err := enc.EndContainer(); err != nil {
		return im.CommandStatus(im.StatusFailure)
	}
	return im.CommandResponse(keySetReadAllIndicesResponseCommandID, enc.Bytes())
}
