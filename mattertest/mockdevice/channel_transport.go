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
	"context"
	"fmt"

	"github.com/cybergarage/go-matter/matter/io"
)

// channelTransport is an io.Transport whose Receive only ever returns bytes
// fed to it by feed (from the single CASE dispatch pump goroutine in
// device.go's serve), and never reads the physical transport directly.
//
// This exists because session.SecureSession.Receive
// (matter/protocol/session/session_impl.go) transparently loops past
// standalone MRP acks and foreign-session packets, re-reading its
// transport internally without ever returning control to its caller — so a
// single imServer.serveOne call can silently pull an unbounded number of
// physical packets, not just the one routed to it. If every CASE session
// shared one physical transport directly, an old session still blocked
// past a trailing ack could silently steal and discard a brand new
// handshake's Sigma1 before the dispatch loop ever saw it. Giving each
// session (and each handshake attempt) its own channel, fed only by the
// single goroutine that actually reads the socket, makes that impossible:
// a session's own internal retry loop can only ever see packets the pump
// decided belong to it.
//
// Receive is unblocked by close, not by its ctx parameter: internally,
// session.SecureSession.Receive always calls its transport's Receive with
// a fresh context.Background() of its own
// (matter/protocol/session/session_impl.go's receiveOne), ignoring
// whatever context the original caller passed in — so a cancelable
// context reaching this far would never actually fire. The CASE dispatch
// pump instead explicitly closes every channelTransport it created once
// its own physical Receive errors (i.e. once Device.Stop closes the
// socket), which is what actually unblocks every session/handshake
// goroutine still waiting on one.
type channelTransport struct {
	tx   io.Transport
	rx   chan []byte
	done chan struct{}
}

// newChannelTransport creates a channelTransport whose Transmit calls are
// forwarded to tx (the real, shared physical transport — safe for
// concurrent use by multiple channelTransports, since UDP writes are).
func newChannelTransport(tx io.Transport) *channelTransport {
	return &channelTransport{tx: tx, rx: make(chan []byte, 4), done: make(chan struct{})}
}

func (t *channelTransport) Transmit(ctx context.Context, b []byte) error {
	return t.tx.Transmit(ctx, b)
}

func (t *channelTransport) Receive(ctx context.Context) ([]byte, error) {
	select {
	case raw := <-t.rx:
		return raw, nil
	case <-t.done:
		return nil, fmt.Errorf("mockdevice: channel transport closed")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// feed hands the pump's next raw datagram to this transport's Receive.
// Buffered so the pump never blocks on a slow/stuck session; also selects
// on done so the pump never blocks feeding a transport whose consumer
// already gave up.
func (t *channelTransport) feed(raw []byte) {
	select {
	case t.rx <- raw:
	case <-t.done:
	}
}

// close unblocks any pending or future Receive call. Safe to call more
// than once.
func (t *channelTransport) close() {
	select {
	case <-t.done:
	default:
		close(t.done)
	}
}
