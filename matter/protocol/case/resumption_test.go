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

	"github.com/cybergarage/go-matter/matter/config"
	"github.com/cybergarage/go-matter/matter/protocol/session"
)

// resumableCASE runs a CASE between an initiator, resuming state when it is
// not nil, and a responder with the store.
func resumableCASE(t *testing.T, admin config.AdministratorConfig, fabrics []ResponderFabric, store ResponderResumptionStore, state *ResumptionState) (responderResult, *Initiator, session.SessionKeys, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	initiatorEnd, responderEnd := newPipe()
	results := make(chan responderResult, 1)
	go func() {
		sess, err := NewResponder(responderEnd, func() ([]ResponderFabric, error) { return fabrics, nil },
			WithResponderResumptionStore(store)).EstablishSession(ctx)
		results <- responderResult{sess: sess, err: err}
	}()
	opts := []Option{WithPeerNodeID(testDeviceNode), WithIPK(testIPK)}
	if state != nil {
		opts = append(opts, WithResumption(state))
	}
	initiator := NewInitiator(initiatorEnd, admin, opts...)
	keys, err := initiator.EstablishSession(ctx)
	return <-results, initiator, keys, err
}

// requireWorkingSession checks that the two sides agree on the keys and
// that they carry messages both ways.
func requireWorkingSession(t *testing.T, res responderResult, keys session.SessionKeys, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("Initiator.EstablishSession() error = %v", err)
	}
	if res.err != nil {
		t.Fatalf("Responder.EstablishSession() error = %v", res.err)
	}
	dev := res.sess
	if !bytes.Equal(dev.Keys.I2RKey(), keys.I2RKey()) || !bytes.Equal(dev.Keys.R2IKey(), keys.R2IKey()) ||
		!bytes.Equal(dev.Keys.AttestationChallenge(), keys.AttestationChallenge()) {
		t.Fatal("the initiator and the responder derived different session keys")
	}
	if dev.Keys.InitiatorSessionID() != keys.InitiatorSessionID() || dev.Keys.ResponderSessionID() != keys.ResponderSessionID() {
		t.Fatal("the initiator and the responder disagree on the session IDs")
	}
	if dev.PeerNodeID != testAdminNode || dev.FabricIndex != testFabricIndex {
		t.Fatalf("responder session with peer 0x%X on fabric %d", dev.PeerNodeID, dev.FabricIndex)
	}
	initiatorEnd, responderEnd := newPipe()
	initiator := session.NewSecureSession(initiatorEnd, keys)
	responder := session.NewSecureSession(responderEnd, dev.Keys, session.WithRole(session.RoleResponder))
	if err := initiator.Transmit(testProtocolPayload(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := responder.Receive(); err != nil {
		t.Fatalf("the responder cannot decrypt the initiator's message: %v", err)
	}
	if err := responder.Transmit(testProtocolPayload(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := initiator.Receive(); err != nil {
		t.Fatalf("the initiator cannot decrypt the responder's message: %v", err)
	}
}

func TestCASEResumesTheSession(t *testing.T) {
	fabric := newTestFabric(t, testFabricID)
	fabrics := []ResponderFabric{fabric.device}
	store := NewResponderResumptionStore()

	res, initiator, keys, err := resumableCASE(t, fabric.admin, fabrics, store, nil)
	requireWorkingSession(t, res, keys, err)
	if initiator.Resumed() || res.sess.Resumed {
		t.Fatal("the first CASE was a resumption")
	}
	first := initiator.ResumptionState()
	if !first.valid() {
		t.Fatal("no resumption state after a full CASE")
	}
	if _, ok := store.Find(first.ResumptionID); !ok {
		t.Fatal("the responder did not keep the session under the resumption ID it offered")
	}

	res, initiator, keys, err = resumableCASE(t, fabric.admin, fabrics, store, first)
	requireWorkingSession(t, res, keys, err)
	if !initiator.Resumed() || !res.sess.Resumed {
		t.Fatalf("resumed: initiator %v, responder %v; want both", initiator.Resumed(), res.sess.Resumed)
	}
	second := initiator.ResumptionState()
	if !second.valid() || bytes.Equal(second.ResumptionID, first.ResumptionID) || !bytes.Equal(second.SharedSecret, first.SharedSecret) {
		t.Fatal("a resumption must give a new resumption ID for the same shared secret")
	}
	if _, ok := store.Find(first.ResumptionID); ok {
		t.Error("the responder kept the resumption ID it replaced")
	}

	// Resuming again works with the new ID, and only with it.
	res, initiator, keys, err = resumableCASE(t, fabric.admin, fabrics, store, second)
	requireWorkingSession(t, res, keys, err)
	if !initiator.Resumed() {
		t.Fatal("the second resumption did not resume")
	}
	res, initiator, keys, err = resumableCASE(t, fabric.admin, fabrics, store, first)
	requireWorkingSession(t, res, keys, err)
	if initiator.Resumed() {
		t.Fatal("a replaced resumption ID resumed a session")
	}
}

func TestCASEFallsBackToAFullCASE(t *testing.T) {
	fabric := newTestFabric(t, testFabricID)
	fabrics := []ResponderFabric{fabric.device}
	store := NewResponderResumptionStore()
	res, initiator, keys, err := resumableCASE(t, fabric.admin, fabrics, store, nil)
	requireWorkingSession(t, res, keys, err)
	known := initiator.ResumptionState()

	tests := []struct {
		name  string
		state *ResumptionState
	}{
		{name: "unknown resumption ID", state: &ResumptionState{ResumptionID: bytes.Repeat([]byte{0x42}, resumptionIDLen), SharedSecret: known.SharedSecret}},
		{name: "wrong shared secret", state: &ResumptionState{ResumptionID: known.ResumptionID, SharedSecret: bytes.Repeat([]byte{0x24}, len(known.SharedSecret))}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, initiator, keys, err := resumableCASE(t, fabric.admin, fabrics, store, tt.state)
			requireWorkingSession(t, res, keys, err)
			if initiator.Resumed() || res.sess.Resumed {
				t.Fatal("the session resumed")
			}
			if !initiator.ResumptionState().valid() {
				t.Fatal("no resumption state after the full CASE")
			}
		})
	}
}

func TestCASEResumesNothingWithoutAStore(t *testing.T) {
	fabric := newTestFabric(t, testFabricID)
	fabrics := []ResponderFabric{fabric.device}
	res, initiator, keys, err := resumableCASE(t, fabric.admin, fabrics, NewResponderResumptionStore(), nil)
	requireWorkingSession(t, res, keys, err)
	// A responder without a store answers a resumption with a full Sigma2.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	initiatorEnd, responderEnd := newPipe()
	results := make(chan responderResult, 1)
	go func() {
		sess, err := NewResponder(responderEnd, func() ([]ResponderFabric, error) { return fabrics, nil }).EstablishSession(ctx)
		results <- responderResult{sess: sess, err: err}
	}()
	again := NewInitiator(initiatorEnd, fabric.admin, WithPeerNodeID(testDeviceNode), WithIPK(testIPK), WithResumption(initiator.ResumptionState()))
	keys, err = again.EstablishSession(ctx)
	requireWorkingSession(t, <-results, keys, err)
	if again.Resumed() {
		t.Fatal("a responder without a store resumed")
	}
}

func TestResponderResumptionStore(t *testing.T) {
	store := NewResponderResumptionStore()
	id := func(b byte) []byte { return bytes.Repeat([]byte{b}, resumptionIDLen) }
	store.Save(ResponderResumption{ResumptionID: id(1), SharedSecret: []byte{1}, FabricIndex: 1, PeerNodeID: 10})
	store.Save(ResponderResumption{ResumptionID: id(2), SharedSecret: []byte{2}, FabricIndex: 1, PeerNodeID: 10})
	if _, ok := store.Find(id(1)); ok {
		t.Error("a second session of the same peer did not replace the first")
	}
	store.Save(ResponderResumption{ResumptionID: id(3), SharedSecret: []byte{3}, FabricIndex: 2, PeerNodeID: 10})
	store.DeleteFabric(1)
	if _, ok := store.Find(id(2)); ok {
		t.Error("DeleteFabric() kept a session of the fabric")
	}
	if _, ok := store.Find(id(3)); !ok {
		t.Error("DeleteFabric() removed a session of another fabric")
	}
	for i := range DefaultResponderResumptions + 4 {
		store.Save(ResponderResumption{ResumptionID: id(byte(10 + i)), SharedSecret: []byte{1}, FabricIndex: 3, PeerNodeID: uint64(100 + i)})
	}
	if _, ok := store.Find(id(10)); ok {
		t.Error("the store kept more than DefaultResponderResumptions sessions")
	}
	if _, ok := store.Find(id(byte(10 + DefaultResponderResumptions + 3))); !ok {
		t.Error("the store dropped its newest session")
	}
}
