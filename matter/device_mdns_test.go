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
	"net"
	"testing"
	"time"
)

func TestMDNSDeviceEffectiveDeadlineBoundsToShorterCtx(t *testing.T) {
	dev := &mDNSDevice{maxDeadline: time.Now().Add(time.Hour)}

	shortCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	got := dev.effectiveDeadline(shortCtx)
	want, _ := shortCtx.Deadline()
	if !got.Equal(want) {
		t.Errorf("effectiveDeadline(...) = %s, want the ctx's own (shorter) deadline %s", got, want)
	}
}

func TestMDNSDeviceEffectiveDeadlineFallsBackToMaxDeadline(t *testing.T) {
	maxDeadline := time.Now().Add(time.Second)
	dev := &mDNSDevice{maxDeadline: maxDeadline}

	got := dev.effectiveDeadline(context.Background())
	if !got.Equal(maxDeadline) {
		t.Errorf("effectiveDeadline(...) = %s, want maxDeadline %s when ctx has no deadline of its own", got, maxDeadline)
	}
}

// TestMDNSDeviceReceiveHonorsPerCallDeadline guards against a real
// regression: once matter/operational_transport.go's resolveOperationalTransport
// could reuse this device's own connection for CASE instead of always
// dialing a fresh one, CASE's Sigma1/Sigma3 retry loop
// (matter/protocol/case/client.go's transmitAndReceiveWithRetry) started
// bounding each attempt to a short per-call ctx — but Receive/Transmit here
// only ever set the connection's read/write deadline once, at connection-
// open time in openConn, to the full commissioning deadline (~120s) and
// never again. A short per-call ctx passed to Receive was therefore
// silently ignored: a real device exchange blocked for the entire remaining
// ~120s on a single Receive call instead of the intended few-second
// per-attempt window, defeating the retry loop's whole purpose.
func TestMDNSDeviceReceiveHonorsPerCallDeadline(t *testing.T) {
	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP(server) error = %v", err)
	}
	defer serverConn.Close()

	clientConn, err := net.DialUDP("udp", nil, serverConn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("DialUDP(client) error = %v", err)
	}
	defer clientConn.Close()

	dev := &mDNSDevice{
		conn: clientConn,
		// Far in the future: if Receive fell back to this instead of
		// honoring the short per-call ctx below, the test would hang
		// (bounded only by the test framework's own timeout), not fail
		// promptly.
		maxDeadline: time.Now().Add(time.Hour),
		readBuf:     make([]byte, 1500),
	}

	shortCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err = dev.Receive(shortCtx)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Receive(...) error = nil, want a timeout (nothing was ever sent)")
	}
	if elapsed > 2*time.Second {
		t.Errorf("Receive(...) took %s to time out, want it bounded to the ~100ms per-call ctx deadline, not maxDeadline (1h)", elapsed)
	}
}
