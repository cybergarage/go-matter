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

package caseprotocol

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	"github.com/cybergarage/go-matter/matter/protocol/session"
)

// sigma1With encodes a Sigma1 whose session-parameter-struct, when put is
// not nil, put writes.
func sigma1With(t *testing.T, put func(enc tlv.Encoder)) []byte {
	t.Helper()
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	_ = enc.PutOctet(tlv.NewContextTag(1), bytes.Repeat([]byte{1}, randomLen))
	enc.PutUnsigned2(tlv.NewContextTag(2), 0x1234)
	_ = enc.PutOctet(tlv.NewContextTag(3), bytes.Repeat([]byte{3}, destinationIDLen))
	_ = enc.PutOctet(tlv.NewContextTag(4), bytes.Repeat([]byte{4}, ephPubKeyLen))
	if put != nil {
		enc.BeginStructure(tlv.NewContextTag(5))
		put(enc)
		_ = enc.EndContainer()
	}
	if err := enc.EndContainer(); err != nil {
		t.Fatal(err)
	}
	return enc.Bytes()
}

func TestDecodeSigma1MRPParameters(t *testing.T) {
	ms := time.Millisecond
	tests := []struct {
		name string
		put  func(enc tlv.Encoder)
		want session.MRPParameters
	}{
		{"absent", nil, session.DefaultMRPParameters()},
		{"all", func(enc tlv.Encoder) {
			enc.PutUnsigned4(tlv.NewContextTag(1), 5000)
			enc.PutUnsigned4(tlv.NewContextTag(2), 1000)
			enc.PutUnsigned2(tlv.NewContextTag(3), 2000)
			enc.PutUnsigned1(tlv.NewContextTag(4), 19)
		}, session.MRPParameters{IdleInterval: 5000 * ms, ActiveInterval: 1000 * ms, ActiveThreshold: 2000 * ms}},
		{"idle only", func(enc tlv.Encoder) {
			enc.PutUnsigned4(tlv.NewContextTag(1), 3000)
		}, session.MRPParameters{IdleInterval: 3000 * ms, ActiveInterval: session.DefaultSessionActiveInterval, ActiveThreshold: session.DefaultSessionActiveThreshold}},
		{"over an hour", func(enc tlv.Encoder) {
			enc.PutUnsigned4(tlv.NewContextTag(1), 3_600_001)
			enc.PutUnsigned4(tlv.NewContextTag(2), 0xFFFFFFFF)
		}, session.DefaultMRPParameters()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s1, err := decodeSigma1(sigma1With(t, tt.put))
			if err != nil {
				t.Fatal(err)
			}
			if s1.InitiatorMRP != tt.want {
				t.Fatalf("InitiatorMRP = %+v, want %+v", s1.InitiatorMRP, tt.want)
			}
			if s1.InitiatorSessionID != 0x1234 {
				t.Fatalf("InitiatorSessionID = 0x%04X, want 0x1234 alongside the parameters", s1.InitiatorSessionID)
			}
		})
	}
}

// TestInitiatorTakesResponderMRPParameters checks that the CASE initiator
// learns the MRP parameters the responder announces in its Sigma2, and the
// responder those of the initiator's Sigma1.
func TestInitiatorTakesResponderMRPParameters(t *testing.T) {
	fabric := newTestFabric(t, testFabricID)
	sleepy := session.MRPParameters{IdleInterval: 15 * time.Second, ActiveInterval: 500 * time.Millisecond, ActiveThreshold: 2 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	initiatorEnd, responderEnd := newPipe()
	results := make(chan responderResult, 1)
	go func() {
		sess, err := NewResponder(responderEnd, func() ([]ResponderFabric, error) { return []ResponderFabric{fabric.device}, nil },
			WithResponderMRPParameters(sleepy)).EstablishSession(ctx)
		results <- responderResult{sess: sess, err: err}
	}()
	initiator := NewInitiator(initiatorEnd, fabric.admin, WithPeerNodeID(testDeviceNode), WithIPK(testIPK))
	if _, err := initiator.EstablishSession(ctx); err != nil {
		t.Fatalf("Initiator.EstablishSession() error = %v", err)
	}
	res := <-results
	if res.err != nil {
		t.Fatalf("Responder.EstablishSession() error = %v", res.err)
	}
	if got := initiator.PeerMRPParameters(); got != sleepy {
		t.Fatalf("Initiator.PeerMRPParameters() = %+v, want %+v", got, sleepy)
	}
	if got := res.sess.PeerMRP; got != session.DefaultMRPParameters() {
		t.Fatalf("ResponderSession.PeerMRP = %+v, want the initiator's defaults", got)
	}
}
