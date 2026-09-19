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
	"net"
	"time"
)

// pipeTransport adapts a net.Conn (from net.Pipe()) to io.Transport for
// tests that need two sides of the real protocol stack talking to each
// other in-process, without a real UDP socket. net.Pipe is synchronous and
// unbuffered: a Write blocks until fully consumed by a matching Read, so as
// long as callers never issue overlapping/pipelined writes on the same
// side (true for every request/response protocol phase used here), one
// Receive call returns exactly the bytes of one Transmit call — datagram
// framing is preserved despite net.Conn's stream-oriented interface.
type pipeTransport struct {
	conn net.Conn
}

func newPipeTransportPair() (*pipeTransport, *pipeTransport) {
	c1, c2 := net.Pipe()
	return &pipeTransport{conn: c1}, &pipeTransport{conn: c2}
}

func (p *pipeTransport) Transmit(ctx context.Context, b []byte) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Time{}
	}
	_ = p.conn.SetWriteDeadline(deadline)
	_, err := p.conn.Write(b)
	return err
}

func (p *pipeTransport) Receive(ctx context.Context) ([]byte, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Time{}
	}
	_ = p.conn.SetReadDeadline(deadline)
	buf := make([]byte, 16*1024)
	n, err := p.conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (p *pipeTransport) Close() error {
	return p.conn.Close()
}
