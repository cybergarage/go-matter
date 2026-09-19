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

package mockdevice

import (
	"errors"
	"io"
	"testing"

	"github.com/cybergarage/go-matter/matter/cluster/generalcommissioning"
	"github.com/cybergarage/go-matter/matter/protocol/im"
	"github.com/cybergarage/go-matter/matter/protocol/session"
)

// newFabricatedSessionPair builds a client/device session.SecureSession
// pair sharing hand-fabricated (not PASE/CASE-derived) but mutually
// consistent keys, for tests that want to isolate one layer (here, the IM
// server) from the handshake layers below it.
func newFabricatedSessionPair(t *testing.T) (session.SecureSession, session.SecureSession) {
	t.Helper()
	clientTransport, deviceTransport := newPipeTransportPair()
	t.Cleanup(func() {
		_ = clientTransport.Close()
		_ = deviceTransport.Close()
	})
	clientKeys := simpleSessionKeys{
		i2rKey:               bytesOf(0x01, 16),
		r2iKey:               bytesOf(0x02, 16),
		attestationChallenge: bytesOf(0x03, 16),
		initiatorSessionID:   100,
		responderSessionID:   200,
		localNodeID:          0,
		peerNodeID:           0,
	}
	clientSess := session.NewSecureSession(clientTransport, clientKeys)
	deviceSess := session.NewSecureSession(deviceTransport, swapRoleSessionKeys(clientKeys))
	return clientSess, deviceSess
}

func bytesOf(v byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = v
	}
	return out
}

// serveContinuously runs srv.serveOne() in a loop on a background goroutine
// until t's cleanup closes the underlying transport.
//
// A single serveOne() call per client operation is not enough:
// session.SecureSession.Receive() (matter/protocol/session/session_impl.go)
// automatically sends a standalone MRP ack for every reliable message it
// receives, and automatically discards incoming standalone acks while
// waiting for the next real message. Over the synchronous, unbuffered
// net.Pipe() this package's tests use, that ack write blocks until the
// device side is back inside a Receive() call — which only holds if the
// server keeps calling serveOne() continuously, not once per expected
// request.
func serveContinuously(t *testing.T, srv *imServer) {
	t.Helper()
	go func() {
		for {
			if err := srv.serveOne(); err != nil {
				if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
					return
				}
				t.Logf("srv.serveOne() error = %v", err)
				return
			}
		}
	}()
}

func TestGeneralCommissioningHandlers(t *testing.T) {
	clientSess, deviceSess := newFabricatedSessionPair(t)

	srv := newIMServer(deviceSess)
	var completed bool
	registerGeneralCommissioningHandlers(srv, func() { completed = true })
	serveContinuously(t, srv)

	ok, err := im.ReadBoolAttribute(clientSess, defaultEndpointID, generalCommissioningClusterID, supportsConcurrentConnectionAttributeID)
	if err != nil {
		t.Fatalf("ReadBoolAttribute(SupportsConcurrentConnection) error = %v", err)
	}
	if !ok {
		t.Error("SupportsConcurrentConnection = false, want true")
	}

	if err := generalcommissioning.ArmFailSafe(clientSess, defaultEndpointID, 60, 1); err != nil {
		t.Fatalf("ArmFailSafe() error = %v", err)
	}

	if err := generalcommissioning.CommissioningComplete(clientSess, defaultEndpointID); err != nil {
		t.Fatalf("CommissioningComplete() error = %v", err)
	}

	if !completed {
		t.Error("onCommissioningComplete callback was not invoked")
	}
}
