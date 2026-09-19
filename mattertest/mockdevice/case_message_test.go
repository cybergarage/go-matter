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
	"testing"

	"github.com/cybergarage/go-matter/matter/encoding/message"
)

// TestBuildCASEMessageAckCounterMatchesAcknowledgedMessage guards against
// the exact regression this whole project's CASE work hit against a real
// device: Sigma3 (client-side) claiming to ack a message via a bare
// AckFlag with no ack counter actually behind it, so the wire message
// acked message counter 0 instead of the real one — a real device's MRP
// layer never recognized the previous message as acknowledged and
// retransmitted it, which then arrived interleaved with the next exchange.
// Sigma2 and SigmaFinished (this mock's own outgoing acks, of Sigma1 and
// Sigma3 respectively) are exactly as exposed to this bug class as Sigma3
// was, so this pins the same property here.
func TestBuildCASEMessageAckCounterMatchesAcknowledgedMessage(t *testing.T) {
	const wantAckCounter = message.MessageCounter(0x0BADF00D)
	msg, err := buildCASEMessage(message.CASESigma2, 1, []byte("payload"), true, wantAckCounter)
	if err != nil {
		t.Fatalf("buildCASEMessage(...) error = %v", err)
	}
	if !msg.IsAck() {
		t.Fatal("buildCASEMessage(hasAck=true, ...) did not set the exchange header's ack flag")
	}
	got, ok := msg.AckMessageCounter()
	if !ok {
		t.Fatal("buildCASEMessage(hasAck=true, ...) message has no ack counter")
	}
	if got != wantAckCounter {
		t.Errorf("AckMessageCounter() = 0x%08X, want 0x%08X", uint32(got), uint32(wantAckCounter))
	}

	noAckMsg, err := buildCASEMessage(message.CASESigma1, 1, []byte("payload"), false, 0)
	if err != nil {
		t.Fatalf("buildCASEMessage(...) error = %v", err)
	}
	if noAckMsg.IsAck() {
		t.Error("buildCASEMessage(hasAck=false, ...) set the exchange header's ack flag")
	}
}
