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
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	"github.com/cybergarage/go-matter/matter/protocol/im"
	"github.com/cybergarage/go-matter/matter/protocol/session"
)

// nodeImpl wraps a live CASE SecureSession with the identity of the node it
// is connected to. An im.ExchangeMux reads the session, so requests and
// subscriptions share it. When the session fails, or the node stops
// answering on it, connect establishes a new one, and the subscriptions
// move over to it.
type nodeImpl struct {
	nodeID   NodeID
	fabricID uint64
	connect  nodeConnector

	mutex   sync.Mutex
	mux     *im.ExchangeMux
	resumed bool
	closed  bool
	// reconnecting is closed when the reconnection in progress ends; nil
	// while none is.
	reconnecting chan struct{}
}

// nodeConnector establishes a new CASE session with the node, and tells
// whether it resumed the last one.
type nodeConnector func(ctx context.Context) (session.SecureSession, bool, error)

// ErrNodeClosed is returned by a node's methods after Close.
var ErrNodeClosed = fmt.Errorf("%w: the node is closed", im.ErrSubscriptionClosed)

func newNode(nodeID NodeID, fabricID uint64, sess session.SecureSession, resumed bool, connect nodeConnector) *nodeImpl {
	return &nodeImpl{
		nodeID:       nodeID,
		fabricID:     fabricID,
		connect:      connect,
		mutex:        sync.Mutex{},
		mux:          im.NewExchangeMux(sess),
		resumed:      resumed,
		closed:       false,
		reconnecting: nil,
	}
}

// currentMux returns the mux of the node's session, connecting again first
// when that session failed. A session which stopped answering is not taken
// for failed here: a request is not repeated, as it may have taken effect.
func (n *nodeImpl) currentMux() *im.ExchangeMux {
	n.mutex.Lock()
	mux, closed := n.mux, n.closed
	n.mutex.Unlock()
	if closed || mux.Err() == nil || n.connect == nil {
		return mux
	}
	ctx, cancel := context.WithTimeout(context.Background(), DefaultConnectTimeout)
	defer cancel()
	next, err := n.reconnectFrom(ctx, mux)
	if err != nil {
		log.Warnf("matter: node 0x%016X: reconnect: %v", uint64(n.nodeID), err)
		return mux
	}
	return next
}

// Reconnect establishes a new CASE session with the node in place of the
// current one, resuming it when the node allows, and moves the node's
// subscriptions over to it.
func (n *nodeImpl) Reconnect(ctx context.Context) error {
	n.mutex.Lock()
	mux := n.mux
	n.mutex.Unlock()
	_, err := n.reconnectFrom(ctx, mux)
	return err
}

// Resumed reports whether the node's current session resumed an earlier
// one (4.14.2.2. Session Resumption) rather than running a full CASE.
func (n *nodeImpl) Resumed() bool {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	return n.resumed
}

// reconnectFrom replaces failed with a new session, once however many
// callers ask at the same time: when failed is no longer the node's
// session, it returns the one which replaced it. It is the
// im.ReconnectFunc of the node's subscriptions.
func (n *nodeImpl) reconnectFrom(ctx context.Context, failed *im.ExchangeMux) (*im.ExchangeMux, error) {
	if n.connect == nil {
		return nil, errors.New("matter: the node cannot reconnect")
	}
	for {
		n.mutex.Lock()
		switch {
		case n.closed:
			n.mutex.Unlock()
			return nil, ErrNodeClosed
		case n.mux != failed:
			mux := n.mux
			n.mutex.Unlock()
			return mux, nil
		case n.reconnecting != nil:
			wait := n.reconnecting
			n.mutex.Unlock()
			select {
			case <-wait:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		done := make(chan struct{})
		n.reconnecting = done
		n.mutex.Unlock()
		mux, err := n.replaceSession(ctx, failed)
		n.mutex.Lock()
		n.reconnecting = nil
		close(done)
		n.mutex.Unlock()
		return mux, err
	}
}

// replaceSession closes the transport of failed, which ends its reads and
// tells its subscriptions, and connects a new session.
func (n *nodeImpl) replaceSession(ctx context.Context, failed *im.ExchangeMux) (*im.ExchangeMux, error) {
	closeTransport(failed)
	sess, resumed, err := n.connect(ctx)
	if err != nil {
		return nil, fmt.Errorf("matter: node 0x%016X: reconnect: %w", uint64(n.nodeID), err)
	}
	mux := im.NewExchangeMux(sess)
	n.mutex.Lock()
	if n.closed {
		n.mutex.Unlock()
		_ = mux.Close()
		closeTransport(mux)
		return nil, ErrNodeClosed
	}
	n.mux, n.resumed = mux, resumed
	n.mutex.Unlock()
	how := "a full CASE"
	if resumed {
		how = "a resumed CASE"
	}
	log.Infof("matter: node 0x%016X: reconnected with %s", uint64(n.nodeID), how)
	return mux, nil
}

// closeTransport closes the transport of mux's session, when it is one
// which closes.
func closeTransport(mux *im.ExchangeMux) error {
	if closer, ok := mux.Transport().(interface{ Close() error }); ok {
		return closer.Close()
	}
	return nil
}

// NodeID returns the operational node ID this session is connected to.
func (n *nodeImpl) NodeID() NodeID {
	return n.nodeID
}

// FabricID returns the fabric this node belongs to.
func (n *nodeImpl) FabricID() uint64 {
	return n.fabricID
}

// Session returns the node's CASE secure session, as the im.ExchangeMux
// which reads it.
func (n *nodeImpl) Session() session.SecureSession {
	return n.currentMux()
}

// ReadAttribute reads a single attribute. 10.6.3. AttributeDataIB.
func (n *nodeImpl) ReadAttribute(endpointID im.EndpointID, clusterID im.ClusterID, attributeID im.AttributeID) (*im.ReadResponse, error) {
	return im.ReadAttribute(n.currentMux(), endpointID, clusterID, attributeID)
}

// WriteAttribute writes a single attribute. 10.6.3. AttributeDataIB.
func (n *nodeImpl) WriteAttribute(endpointID im.EndpointID, clusterID im.ClusterID, attributeID im.AttributeID, encodeData func(enc tlv.Encoder) error) (*im.WriteResponse, error) {
	return im.WriteAttribute(n.currentMux(), endpointID, clusterID, attributeID, encodeData)
}

// Invoke invokes a single command. 10.7.9. InvokeRequestMessage.
func (n *nodeImpl) Invoke(endpointID im.EndpointID, clusterID im.ClusterID, commandID im.CommandID, commandFields []byte) (*im.InvokeResponse, error) {
	return im.Invoke(n.currentMux(), endpointID, clusterID, commandID, commandFields)
}

// Close ends the node's subscriptions and closes its session's transport.
// A reconnection in progress fails.
func (n *nodeImpl) Close() error {
	n.mutex.Lock()
	if n.closed {
		n.mutex.Unlock()
		return nil
	}
	n.closed = true
	mux := n.mux
	n.mutex.Unlock()
	_ = mux.Close()
	return closeTransport(mux)
}

// ReadValueAttribute retains complete structured or scalar attribute Data.
// 10.6.3 AttributeDataIB.
func (n *nodeImpl) ReadValueAttribute(ep im.EndpointID, cl im.ClusterID, attr im.AttributeID) (*im.ValueReadResponse, error) {
	return im.ReadValueAttribute(n.currentMux(), ep, cl, attr)
}

var _ ValueAttributeReader = (*nodeImpl)(nil)

// Subscribe subscribes to the attributes of paths; see
// im.ExchangeMux.Subscribe. 8.5. Subscribe Interaction.
//
// The subscription follows the node to a new session when its own fails,
// or when the node stops answering on it, such as after a restart.
func (n *nodeImpl) Subscribe(ctx context.Context, paths []im.AttributeRequestPath, handler im.ReportHandler, opts ...im.SubscribeOption) (*im.Subscription, error) {
	if n.connect != nil {
		opts = append([]im.SubscribeOption{im.WithReconnect(n.reconnectFrom)}, opts...)
	}
	return n.currentMux().Subscribe(ctx, paths, handler, opts...)
}

var _ AttributeSubscriber = (*nodeImpl)(nil)

// ReadEvents reads the events of paths the node keeps. 7.14. Event.
func (n *nodeImpl) ReadEvents(paths []im.EventRequestPath, opts ...im.ReadEventsOption) ([]im.EventReport, error) {
	return im.ReadEvents(n.currentMux(), paths, opts...)
}

var _ EventReader = (*nodeImpl)(nil)

var _ Reconnector = (*nodeImpl)(nil)
