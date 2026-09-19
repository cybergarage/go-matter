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
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/cybergarage/go-matter/matter/protocol/pase"
	"github.com/cybergarage/go-matter/matter/protocol/session"
	"github.com/cybergarage/go-matter/matter/types"
)

// TestHandlePASEInteropsWithRealInitiator runs this mock device's PASE
// responder against the real, production matter/protocol/pase.Initiator
// over an in-process pipe, and proves the two sides actually agree on
// working session keys by exchanging an AES-CCM-encrypted message in both
// directions through session.SecureSession — not just comparing derived
// key bytes for equality, but confirming real interoperability. This is
// the earliest point in the mock-device build-out where production
// initiator code can validate this package's independently-written
// responder logic end to end.
func TestHandlePASEInteropsWithRealInitiator(t *testing.T) {
	initiatorTransport, deviceTransport := newPipeTransportPair()
	t.Cleanup(func() {
		_ = initiatorTransport.Close()
		_ = deviceTransport.Close()
	})

	const passcodeValue = 20202021
	passcode := types.NewPasscode(passcodeValue)

	type deviceResult struct {
		sess session.SecureSession
		err  error
	}
	deviceCtx, deviceCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer deviceCancel()
	deviceDone := make(chan deviceResult, 1)
	go func() {
		sess, err := handlePASE(deviceCtx, deviceTransport, passcode)
		deviceDone <- deviceResult{sess: sess, err: err}
	}()

	initiator := pase.NewInitiator(initiatorTransport, pase.Passcode(passcode))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	initiatorKeys, initiatorErr := initiator.EstablishSession(ctx)

	var deviceRes deviceResult
	select {
	case deviceRes = <-deviceDone:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for handlePASE to finish")
	}
	if initiatorErr != nil {
		t.Fatalf("initiator EstablishSession() error = %v (device error = %v)", initiatorErr, deviceRes.err)
	}
	if deviceRes.err != nil {
		t.Fatalf("handlePASE() error = %v", deviceRes.err)
	}

	initiatorSess := session.NewSecureSession(initiatorTransport, initiatorKeys)
	deviceSess := deviceRes.sess

	// net.Pipe() is synchronous: Transmit/Receive on the two ends must run
	// concurrently, or the Transmit blocks forever waiting for a Receive
	// that the same goroutine hasn't reached yet.
	initiatorToDevice := []byte("hello from initiator")
	recvDone := make(chan struct {
		b   []byte
		err error
	}, 1)
	go func() {
		b, err := deviceSess.Receive()
		recvDone <- struct {
			b   []byte
			err error
		}{b, err}
	}()
	if err := initiatorSess.Transmit(initiatorToDevice); err != nil {
		t.Fatalf("initiator Transmit() error = %v", err)
	}
	recv1 := <-recvDone
	if recv1.err != nil {
		t.Fatalf("device Receive() error = %v", recv1.err)
	}
	if !bytes.Equal(recv1.b, initiatorToDevice) {
		t.Errorf("device received %q, want %q", recv1.b, initiatorToDevice)
	}

	deviceToInitiator := []byte("hello from device")
	go func() {
		b, err := initiatorSess.Receive()
		recvDone <- struct {
			b   []byte
			err error
		}{b, err}
	}()
	if err := deviceSess.Transmit(deviceToInitiator); err != nil {
		t.Fatalf("device Transmit() error = %v", err)
	}
	recv2 := <-recvDone
	if recv2.err != nil {
		t.Fatalf("initiator Receive() error = %v", recv2.err)
	}
	if !bytes.Equal(recv2.b, deviceToInitiator) {
		t.Errorf("initiator received %q, want %q", recv2.b, deviceToInitiator)
	}
}
