// Copyright (C) 2024 The go-matter Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package matter

import (
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	"github.com/cybergarage/go-matter/matter/protocol/im"
	"github.com/cybergarage/go-matter/matter/protocol/session"
	"github.com/cybergarage/go-matter/matter/types"
)

// NodeID represents a node ID.
// 2.5.5. Node Identifier (NID).
type NodeID = types.NodeID

// Node represents a live connection to an already-commissioned Node,
// established via Commissioner.Connect. Unlike Commissionee — the transient
// view of a device mid-commissioning, tied to a discovery-time Device —
// Node wraps the operational CASE SecureSession itself, so a caller can
// issue Interaction Model Read/Write/Invoke requests directly. Callers
// needing a specific cluster's client function (e.g. matter/cluster/descriptor,
// matter/cluster/basicinformation) pass Session() to it directly, the same
// way commissioning_impl.go already calls cluster functions with an
// explicit session.SecureSession.
type Node interface {
	// NodeID returns the operational node ID this session is connected to.
	NodeID() NodeID
	// FabricID returns the fabric this node belongs to.
	FabricID() uint64
	// Session returns the underlying CASE secure session.
	Session() session.SecureSession
	// ReadAttribute reads a single attribute. 10.6.3. AttributeDataIB.
	ReadAttribute(endpointID im.EndpointID, clusterID im.ClusterID, attributeID im.AttributeID) (*im.ReadResponse, error)
	// WriteAttribute writes a single attribute. 10.6.3. AttributeDataIB.
	WriteAttribute(endpointID im.EndpointID, clusterID im.ClusterID, attributeID im.AttributeID, encodeData func(enc tlv.Encoder) error) (*im.WriteResponse, error)
	// Invoke invokes a single command. 10.7.9. InvokeRequestMessage.
	Invoke(endpointID im.EndpointID, clusterID im.ClusterID, commandID im.CommandID, commandFields []byte) (*im.InvokeResponse, error)
	// Close closes the underlying CASE session's transport.
	Close() error
}
