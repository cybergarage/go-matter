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

package store

import "time"

// Fabric indexes as a device assigns them (Matter Core 7.5.2): 0 means "no
// fabric" and 255 is reserved, so a stored fabric is always 1..254.
const (
	MinFabricIndex uint8 = 1
	MaxFabricIndex uint8 = 254
)

// DeviceFabricRecord is what a device keeps about one fabric it has joined:
// one row of the Operational Credentials cluster's Fabrics and NOCs lists,
// plus the operational private key that goes with the NOC.
type DeviceFabricRecord struct {
	FabricIndex   uint8  `json:"fabricIndex"`
	FabricID      uint64 `json:"fabricId"`
	NodeID        uint64 `json:"nodeId"`
	VendorID      uint16 `json:"vendorId"`
	RootPublicKey []byte `json:"rootPublicKey"`
	Label         string `json:"label,omitempty"`
	RCAC          []byte `json:"rcac"`
	ICAC          []byte `json:"icac,omitempty"`
	NOC           []byte `json:"noc"`
	// PrivateKey is the operational private key the NOC was issued for.
	// It is stored with the record, as FabricRecord stores the
	// commissioner's; keeping it in a secure element instead is left to a
	// KVStore that does so, or to a later signer abstraction.
	PrivateKey []byte    `json:"privateKey"`
	UpdatedAt  time.Time `json:"updatedAt"`
}

// Privilege is an Access Control privilege (Matter Core 9.10.5.2).
type Privilege uint8

const (
	PrivilegeView       Privilege = 1
	PrivilegeProxyView  Privilege = 2
	PrivilegeOperate    Privilege = 3
	PrivilegeManage     Privilege = 4
	PrivilegeAdminister Privilege = 5
)

// AuthMode is an Access Control authentication mode (Matter Core
// 9.10.5.3).
type AuthMode uint8

const (
	AuthModePASE  AuthMode = 1
	AuthModeCASE  AuthMode = 2
	AuthModeGroup AuthMode = 3
)

// ACLEntry is one AccessControlEntryStruct (Matter Core 9.10.5.5). The
// fabric it belongs to is not a field: entries are stored per fabric.
type ACLEntry struct {
	Privilege Privilege `json:"privilege"`
	AuthMode  AuthMode  `json:"authMode"`
	// Subjects are node IDs, CATs or group IDs depending on AuthMode;
	// empty means any subject authenticated with AuthMode.
	Subjects []uint64 `json:"subjects,omitempty"`
	// Targets restrict the entry to clusters, endpoints or device types;
	// empty means every target.
	Targets []ACLTarget `json:"targets,omitempty"`
}

// ACLTarget is one AccessControlTargetStruct (Matter Core 9.10.5.4). A nil
// field is a null in the struct.
type ACLTarget struct {
	Cluster    *uint32 `json:"cluster,omitempty"`
	Endpoint   *uint16 `json:"endpoint,omitempty"`
	DeviceType *uint32 `json:"deviceType,omitempty"`
}

// GroupKeySecurityPolicy is a GroupKeySetStruct's GroupKeySecurityPolicy
// (Matter Core 11.2.5.1).
type GroupKeySecurityPolicy uint8

const (
	GroupKeySecurityPolicyTrustFirst   GroupKeySecurityPolicy = 0
	GroupKeySecurityPolicyCacheAndSync GroupKeySecurityPolicy = 1
)

// MaxEpochKeys is the number of epoch keys a group key set holds.
const MaxEpochKeys = 3

// EpochKey is one epoch key of a group key set and the time, in
// microseconds since the Matter epoch, it starts being used.
type EpochKey struct {
	Key       []byte `json:"key"`
	StartTime uint64 `json:"startTime"`
}

// GroupKeySet is one GroupKeySetStruct (Matter Core 11.2.5.2). The key set
// with ID 0 is the fabric's IPK.
type GroupKeySet struct {
	GroupKeySetID  uint16                 `json:"groupKeySetId"`
	SecurityPolicy GroupKeySecurityPolicy `json:"securityPolicy"`
	// EpochKeys holds one to MaxEpochKeys keys, oldest first.
	EpochKeys []EpochKey `json:"epochKeys"`
}

// GroupKeyMapEntry maps a group to the key set its messages use (Matter
// Core 11.2.5.3).
type GroupKeyMapEntry struct {
	GroupID       uint16 `json:"groupId"`
	GroupKeySetID uint16 `json:"groupKeySetId"`
}

// GroupRecord is a group the node's endpoints joined with the Groups
// cluster, a GroupInfoMapStruct of the Group Key Management cluster's
// GroupTable.
type GroupRecord struct {
	GroupID   uint16   `json:"groupId"`
	Name      string   `json:"name,omitempty"`
	Endpoints []uint16 `json:"endpoints"`
}

// GroupKeysRecord is a fabric's Group Key Management state: its key sets,
// which group uses which set, and which endpoints are in which group.
type GroupKeysRecord struct {
	KeySets []GroupKeySet      `json:"keySets,omitempty"`
	KeyMap  []GroupKeyMapEntry `json:"keyMap,omitempty"`
	Groups  []GroupRecord      `json:"groups,omitempty"`
}

// SceneRecord is a scene a fabric stored on an endpoint, an entry of the
// endpoint's Scenes Management scene table (Matter Application Cluster
// 1.4.7.1).
type SceneRecord struct {
	Endpoint     uint16                 `json:"endpoint"`
	GroupID      uint16                 `json:"groupId"`
	SceneID      uint8                  `json:"sceneId"`
	Name         string                 `json:"name,omitempty"`
	TransitionMs uint32                 `json:"transitionMs,omitempty"`
	Extensions   []SceneExtensionRecord `json:"extensions,omitempty"`
}

// SceneExtensionRecord is the attribute values a scene sets on one
// cluster, an ExtensionFieldSetStruct.
type SceneExtensionRecord struct {
	Cluster uint32                      `json:"cluster"`
	Values  []SceneAttributeValueRecord `json:"values,omitempty"`
}

// SceneAttributeValueRecord is the value a scene sets one attribute to,
// an AttributeValuePairStruct: an unsigned or signed integer of Bits bits.
type SceneAttributeValueRecord struct {
	Attribute uint32 `json:"attribute"`
	Value     uint64 `json:"value"`
	Signed    bool   `json:"signed,omitempty"`
	Bits      int    `json:"bits"`
}
