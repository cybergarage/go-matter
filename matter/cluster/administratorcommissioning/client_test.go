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

package administratorcommissioning

import (
	"errors"
	"testing"
	"time"

	"github.com/cybergarage/go-matter/matter/encoding"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	"github.com/cybergarage/go-matter/matter/protocol/im"
	"github.com/cybergarage/go-matter/matter/types"
)

func TestNewWindow(t *testing.T) {
	seen := map[uint32]bool{}
	for range 20 {
		w, err := NewWindow(0xFFF1, 0x8000)
		if err != nil {
			t.Fatal(err)
		}
		if err := encoding.ValidatePasscode(w.Passcode); err != nil {
			t.Fatalf("passcode: %v", err)
		}
		if w.Discriminator > 0x0FFF {
			t.Fatalf("discriminator 0x%X", w.Discriminator)
		}
		if err := w.Verifier.Validate(); err != nil || w.Verifier.Iterations != DefaultIterations {
			t.Fatalf("verifier: %v, %d iterations", err, w.Verifier.Iterations)
		}
		if w.QRCode.VendorID() != 0xFFF1 || w.QRCode.Passcode() != types.Passcode(w.Passcode) || w.ManualPairingCode.Passcode() != types.Passcode(w.Passcode) {
			t.Fatalf("codes do not carry the window: %s %s", w.QRCode, w.ManualPairingCode)
		}
		seen[w.Passcode] = true
	}
	if len(seen) < 19 {
		t.Fatalf("%d distinct passcodes in 20 windows", len(seen))
	}
}

func TestOpenCommissioningWindowFields(t *testing.T) {
	w, err := NewWindow(1, 2)
	if err != nil {
		t.Fatal(err)
	}
	b, err := buildOpenCommissioningWindowFields(w, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	dec := tlv.NewDecoderWithBytes(b)
	got := map[uint8]tlv.Element{}
	for dec.Next() {
		e := dec.Element()
		if tag, ok := e.Tag().(tlv.ContextTag); ok && !e.Type().IsStructure() {
			got[uint8(tag.ContextNumber())] = e
		}
	}
	if v, _ := got[0].Unsigned(); v != 300 {
		t.Fatalf("CommissioningTimeout = %d, want 300", v)
	}
	if v, _ := got[1].Bytes(); string(v) != string(w.Verifier.Bytes()) || len(v) != 97 {
		t.Fatalf("PAKEPasscodeVerifier is %d bytes", len(v))
	}
	if v, _ := got[2].Unsigned(); v != uint64(w.Discriminator) {
		t.Fatalf("Discriminator = %d", v)
	}
	if v, _ := got[3].Unsigned(); v != uint64(DefaultIterations) {
		t.Fatalf("Iterations = %d", v)
	}
	if v, _ := got[4].Bytes(); string(v) != string(w.Verifier.Salt) {
		t.Fatal("Salt differs")
	}

	if err := OpenCommissioningWindow(nil, 0, w, 16*time.Minute); err == nil {
		t.Fatal("a 16-minute window accepted")
	}
	if err := OpenBasicCommissioningWindow(nil, 0, time.Minute); err == nil {
		t.Fatal("a 1-minute basic window accepted")
	}
	if err := OpenCommissioningWindow(nil, 0, Window{}, 3*time.Minute); err == nil {
		t.Fatal("a window without a verifier accepted")
	}
}

func TestStatusError(t *testing.T) {
	for status, want := range map[uint8]error{statusBusy: ErrBusy, statusPAKEParameterError: ErrPAKEParameterError, statusWindowNotOpen: ErrWindowNotOpen} {
		resp := &im.InvokeResponse{Status: im.InvokeStatus{IMStatus: 1, ClusterStatus: status}}
		if err := statusError("X", resp); !errors.Is(err, want) {
			t.Fatalf("cluster status %d: %v, want %v", status, err, want)
		}
	}
	if err := statusError("X", &im.InvokeResponse{Status: im.InvokeStatus{IMStatus: 0x7E}}); err == nil {
		t.Fatal("a failure taken as success")
	}
	if err := statusError("X", &im.InvokeResponse{}); err != nil {
		t.Fatalf("success: %v", err)
	}
}
