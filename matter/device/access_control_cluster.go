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
	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter/credentials"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	"github.com/cybergarage/go-matter/matter/protocol/im"
	"github.com/cybergarage/go-matter/matter/store"
)

// Access Control cluster (Matter Core 9.10).
const (
	AccessControlClusterID im.ClusterID = 0x001F

	aclAttributeID                           im.AttributeID = 0x0000
	subjectsPerAccessControlEntryAttributeID im.AttributeID = 0x0002
	targetsPerAccessControlEntryAttributeID  im.AttributeID = 0x0003
	accessControlEntriesPerFabricAttributeID im.AttributeID = 0x0004

	accessControlClusterRevision = 1

	// The limits the device supports, the minimums Matter requires
	// (9.10.6.3 to 9.10.6.5).
	subjectsPerAccessControlEntry = 4
	targetsPerAccessControlEntry  = 3
	accessControlEntriesPerFabric = 4

	// maxGroupID is the largest group ID a Group subject may name.
	maxGroupID = 0xFFFF
)

// AccessControlEntryStruct field tags (9.10.4.5).
const (
	aclPrivilegeTag = 1
	aclAuthModeTag  = 2
	aclSubjectsTag  = 3
	aclTargetsTag   = 4

	aclTargetClusterTag    = 0
	aclTargetEndpointTag   = 1
	aclTargetDeviceTypeTag = 2
)

// accessControl is the server of the Access Control cluster: it reports
// and replaces the ACL entries of the accessing fabric, which checkAccess
// grants access by.
type accessControl struct {
	oc *operationalCredentials
}

func (ac *accessControl) register(srv *im.Server) {
	administer := im.WithPrivilege(im.PrivilegeAdminister)
	srv.HandleAttributeRead(rootEndpoint, AccessControlClusterID, aclAttributeID, ac.readACL, administer)
	srv.HandleAttributeWrite(rootEndpoint, AccessControlClusterID, aclAttributeID, ac.writeACL, administer)
	for attribute, v := range map[im.AttributeID]uint16{
		subjectsPerAccessControlEntryAttributeID: subjectsPerAccessControlEntry,
		targetsPerAccessControlEntryAttributeID:  targetsPerAccessControlEntry,
		accessControlEntriesPerFabricAttributeID: accessControlEntriesPerFabric,
		clusterRevisionAttributeID:               accessControlClusterRevision,
	} {
		srv.HandleAttribute(rootEndpoint, AccessControlClusterID, attribute, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
			enc.PutUnsigned2(tag, v)
			return im.StatusSuccess
		})
	}
	srv.HandleAttribute(rootEndpoint, AccessControlClusterID, featureMapAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		enc.PutUnsigned4(tag, 0)
		return im.StatusSuccess
	})
}

// readACL reports the ACL of every fabric, or of the accessing one for a
// fabric-filtered read. The fields of the entries are fabric-sensitive:
// an entry of another fabric carries only its FabricIndex (7.13.6).
func (ac *accessControl) readACL(req *im.AttributeRequest, enc tlv.Encoder, tag tlv.Tag) im.Status {
	fabrics, accessing, err := ac.oc.scopedFabrics(req)
	if err != nil {
		return im.StatusFailure
	}
	enc.BeginArray(tag)
	for _, f := range fabrics {
		entries, err := ac.oc.aclEntries(f.FabricIndex)
		if err != nil {
			log.Errorf("device: load the ACL of fabric %d: %v", f.FabricIndex, err)
			return im.StatusFailure
		}
		for _, entry := range entries {
			enc.BeginStructure(tlv.NewAnonymousTag())
			if f.FabricIndex == accessing {
				if err := encodeACLEntryFields(enc, entry); err != nil {
					return im.StatusFailure
				}
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

func encodeACLEntryFields(enc tlv.Encoder, entry store.ACLEntry) error {
	enc.PutUnsigned1(tlv.NewContextTag(aclPrivilegeTag), uint8(entry.Privilege))
	enc.PutUnsigned1(tlv.NewContextTag(aclAuthModeTag), uint8(entry.AuthMode))
	if entry.Subjects == nil {
		enc.PutNull(tlv.NewContextTag(aclSubjectsTag))
	} else {
		enc.BeginArray(tlv.NewContextTag(aclSubjectsTag))
		for _, subject := range entry.Subjects {
			enc.PutUnsigned8(tlv.NewAnonymousTag(), subject)
		}
		if err := enc.EndContainer(); err != nil {
			return err
		}
	}
	if entry.Targets == nil {
		enc.PutNull(tlv.NewContextTag(aclTargetsTag))
		return nil
	}
	enc.BeginArray(tlv.NewContextTag(aclTargetsTag))
	for _, target := range entry.Targets {
		enc.BeginStructure(tlv.NewAnonymousTag())
		if target.Cluster == nil {
			enc.PutNull(tlv.NewContextTag(aclTargetClusterTag))
		} else {
			enc.PutUnsigned4(tlv.NewContextTag(aclTargetClusterTag), *target.Cluster)
		}
		if target.Endpoint == nil {
			enc.PutNull(tlv.NewContextTag(aclTargetEndpointTag))
		} else {
			enc.PutUnsigned2(tlv.NewContextTag(aclTargetEndpointTag), *target.Endpoint)
		}
		if target.DeviceType == nil {
			enc.PutNull(tlv.NewContextTag(aclTargetDeviceTypeTag))
		} else {
			enc.PutUnsigned4(tlv.NewContextTag(aclTargetDeviceTypeTag), *target.DeviceType)
		}
		if err := enc.EndContainer(); err != nil {
			return err
		}
	}
	return enc.EndContainer()
}

// writeACL replaces the ACL of the accessing fabric, or appends an entry
// to it (9.10.6.2). The entries of the other fabrics are untouched. While
// the fail-safe is armed the change goes through its transaction, like
// every other change commissioning makes.
func (ac *accessControl) writeACL(req *im.AttributeWriteRequest) im.Status {
	fabricIndex := ac.oc.accessingFabric(req.Session)
	if fabricIndex == 0 {
		return im.StatusUnsupportedAccess
	}
	dec, elem, err := req.Decoder()
	if err != nil {
		return im.StatusInvalidDataType
	}
	var entries []store.ACLEntry
	switch {
	case req.Append && elem.Type().IsStructure():
		entry, status := decodeACLEntry(dec)
		if status != im.StatusSuccess {
			return status
		}
		entries = []store.ACLEntry{entry}
	case !req.Append && elem.Type().IsArray():
		entries = []store.ACLEntry{}
		for dec.Next() {
			item := dec.Element()
			if item.Type().IsEndOfContainer() {
				break
			}
			if !item.Type().IsStructure() {
				return im.StatusInvalidDataType
			}
			entry, status := decodeACLEntry(dec)
			if status != im.StatusSuccess {
				return status
			}
			entries = append(entries, entry)
		}
		if dec.Error() != nil {
			return im.StatusInvalidDataType
		}
	default:
		return im.StatusInvalidDataType
	}

	oc := ac.oc
	oc.mutex.Lock()
	defer oc.mutex.Unlock()
	var w interface {
		store.DeviceStoreReader
		store.DeviceStoreWriter
	} = oc.store
	if tx := oc.armedLocked(); tx != nil {
		w = tx
	}
	if req.Append {
		current, err := w.LoadACL(fabricIndex)
		if err != nil {
			return im.StatusFailure
		}
		entries = append(current, entries...)
	}
	if accessControlEntriesPerFabric < len(entries) {
		return im.StatusResourceExhausted
	}
	if err := w.SaveACL(fabricIndex, entries); err != nil {
		log.Errorf("device: write the ACL of fabric %d: %v", fabricIndex, err)
		return im.StatusFailure
	}
	return im.StatusSuccess
}

// decodeACLEntry decodes the AccessControlEntryStruct dec has just
// entered, and checks its constraints (9.10.4.5).
func decodeACLEntry(dec tlv.Decoder) (store.ACLEntry, im.Status) {
	entry := store.ACLEntry{Privilege: 0, AuthMode: 0, Subjects: nil, Targets: nil}
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			break
		}
		tag, _ := contextTagNumber(elem)
		switch {
		case tag == aclPrivilegeTag && elem.Type().IsUnsignedInt():
			v, _ := elem.Unsigned()
			entry.Privilege = store.Privilege(min(v, 0xFF)) // nolint: gosec // bounded above
		case tag == aclAuthModeTag && elem.Type().IsUnsignedInt():
			v, _ := elem.Unsigned()
			entry.AuthMode = store.AuthMode(min(v, 0xFF)) // nolint: gosec // bounded above
		case tag == aclSubjectsTag && elem.Type().IsArray():
			entry.Subjects = []uint64{}
			for dec.Next() {
				item := dec.Element()
				if item.Type().IsEndOfContainer() {
					break
				}
				v, ok := item.Unsigned()
				if !ok {
					return entry, im.StatusInvalidDataType
				}
				entry.Subjects = append(entry.Subjects, v)
			}
		case tag == aclTargetsTag && elem.Type().IsArray():
			entry.Targets = []store.ACLTarget{}
			for dec.Next() {
				item := dec.Element()
				if item.Type().IsEndOfContainer() {
					break
				}
				if !item.Type().IsStructure() {
					return entry, im.StatusInvalidDataType
				}
				target, status := decodeACLTarget(dec)
				if status != im.StatusSuccess {
					return entry, status
				}
				entry.Targets = append(entry.Targets, target)
			}
		case elem.Type().IsContainer():
			if err := skipTLVContainer(dec); err != nil {
				return entry, im.StatusInvalidDataType
			}
		}
	}
	if dec.Error() != nil {
		return entry, im.StatusInvalidDataType
	}
	return entry, validateACLEntry(entry)
}

func decodeACLTarget(dec tlv.Decoder) (store.ACLTarget, im.Status) {
	target := store.ACLTarget{Cluster: nil, Endpoint: nil, DeviceType: nil}
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			break
		}
		if elem.Type().IsNull() {
			continue
		}
		v, ok := elem.Unsigned()
		if !ok {
			return target, im.StatusInvalidDataType
		}
		tag, _ := contextTagNumber(elem)
		switch tag {
		case aclTargetClusterTag:
			if 0xFFFFFFFF < v {
				return target, im.StatusConstraintError
			}
			c := uint32(v)
			target.Cluster = &c
		case aclTargetEndpointTag:
			if 0xFFFF < v {
				return target, im.StatusConstraintError
			}
			e := uint16(v)
			target.Endpoint = &e
		case aclTargetDeviceTypeTag:
			if 0xFFFFFFFF < v {
				return target, im.StatusConstraintError
			}
			d := uint32(v)
			target.DeviceType = &d
		}
	}
	return target, im.StatusSuccess
}

// validateACLEntry checks the constraints of an entry (9.10.4.5): a PASE
// entry is never stored, a Group entry cannot Administer, the subjects
// suit the authentication mode, and a target names a cluster, an
// endpoint or a device type, but not both an endpoint and a device type.
func validateACLEntry(entry store.ACLEntry) im.Status {
	if entry.Privilege < store.PrivilegeView || store.PrivilegeAdminister < entry.Privilege {
		return im.StatusConstraintError
	}
	switch entry.AuthMode {
	case store.AuthModeCASE:
		for _, subject := range entry.Subjects {
			if !credentials.IsOperationalNodeID(subject) && !credentials.IsCASEAuthenticatedTag(subject) {
				return im.StatusConstraintError
			}
		}
	case store.AuthModeGroup:
		if entry.Privilege == store.PrivilegeAdminister {
			return im.StatusConstraintError
		}
		for _, subject := range entry.Subjects {
			if subject == 0 || maxGroupID < subject {
				return im.StatusConstraintError
			}
		}
	default:
		return im.StatusConstraintError
	}
	if subjectsPerAccessControlEntry < len(entry.Subjects) || targetsPerAccessControlEntry < len(entry.Targets) {
		return im.StatusResourceExhausted
	}
	for _, target := range entry.Targets {
		if target.Cluster == nil && target.Endpoint == nil && target.DeviceType == nil {
			return im.StatusConstraintError
		}
		if target.Endpoint != nil && target.DeviceType != nil {
			return im.StatusConstraintError
		}
	}
	return im.StatusSuccess
}

// contextTagNumber returns the context tag number of elem, if it has one.
func contextTagNumber(elem tlv.Element) (uint8, bool) {
	ct, ok := elem.Tag().(tlv.ContextTag)
	if !ok {
		return 0, false
	}
	return uint8(ct.ContextNumber()), true
}

// skipTLVContainer skips the rest of the container dec has just entered.
func skipTLVContainer(dec tlv.Decoder) error {
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
