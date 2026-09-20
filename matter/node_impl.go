// Copyright (C) 2026 The go-matter Authors. All rights reserved.
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
)

// nodeImpl wraps a live CASE SecureSession with the identity of the node it
// is connected to.
type nodeImpl struct {
	nodeID   NodeID
	fabricID uint64
	sess     session.SecureSession
}

func newNode(nodeID NodeID, fabricID uint64, sess session.SecureSession) Node {
	return &nodeImpl{
		nodeID:   nodeID,
		fabricID: fabricID,
		sess:     sess,
	}
}

// NodeID returns the operational node ID this session is connected to.
func (n *nodeImpl) NodeID() NodeID {
	return n.nodeID
}

// FabricID returns the fabric this node belongs to.
func (n *nodeImpl) FabricID() uint64 {
	return n.fabricID
}

// Session returns the underlying CASE secure session.
func (n *nodeImpl) Session() session.SecureSession {
	return n.sess
}

// ReadAttribute reads a single attribute. 10.6.3. AttributeDataIB.
func (n *nodeImpl) ReadAttribute(endpointID im.EndpointID, clusterID im.ClusterID, attributeID im.AttributeID) (*im.ReadResponse, error) {
	return im.ReadAttribute(n.sess, endpointID, clusterID, attributeID)
}

// WriteAttribute writes a single attribute. 10.6.3. AttributeDataIB.
func (n *nodeImpl) WriteAttribute(endpointID im.EndpointID, clusterID im.ClusterID, attributeID im.AttributeID, encodeData func(enc tlv.Encoder) error) (*im.WriteResponse, error) {
	return im.WriteAttribute(n.sess, endpointID, clusterID, attributeID, encodeData)
}

// Invoke invokes a single command. 10.7.9. InvokeRequestMessage.
func (n *nodeImpl) Invoke(endpointID im.EndpointID, clusterID im.ClusterID, commandID im.CommandID, commandFields []byte) (*im.InvokeResponse, error) {
	return im.Invoke(n.sess, endpointID, clusterID, commandID, commandFields)
}

// Close closes the underlying CASE session's transport, mirroring the
// transport-close pattern already used in commissioning_impl.go's
// finalizeCommissioningOverCASE (only a real operational transport
// implements Close(); the type assertion is a no-op for anything that
// doesn't).
func (n *nodeImpl) Close() error {
	if closer, ok := n.sess.Transport().(interface{ Close() error }); ok {
		return closer.Close()
	}
	return nil
}
