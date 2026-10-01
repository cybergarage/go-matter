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

package device

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	"github.com/cybergarage/go-matter/matter/protocol/im"
	"github.com/cybergarage/go-matter/matter/protocol/pase"
	"github.com/cybergarage/go-matter/matter/protocol/session"
	"github.com/cybergarage/go-matter/matter/store"
)

var testEventKey = bytes.Repeat([]byte{0x5A}, testEventEnableKeyLength)

func paseToDevice(t *testing.T, d *Device) session.SecureSession {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := dialDevice(t, d)
	keys, err := pase.NewInitiator(client, testPasscode).EstablishSession(ctx)
	if err != nil {
		t.Fatalf("PASE: %v", err)
	}
	return session.NewSecureSession(client, keys)
}

func readDiagnostic(t *testing.T, sess session.SecureSession, attr im.AttributeID) tlv.Element {
	t.Helper()
	resp, err := im.ReadAttribute(sess, 0, GeneralDiagnosticsClusterID, attr)
	if err != nil || resp.Status != nil {
		t.Fatalf("read General Diagnostics 0x%04X: (%+v, %v)", attr, resp, err)
	}
	return resp.Value
}

func testEventTriggerFields(t *testing.T, key []byte, trigger uint64) []byte {
	t.Helper()
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewContextTag(1))
	if err := enc.PutOctet(tlv.NewContextTag(0), key); err != nil {
		t.Fatal(err)
	}
	enc.PutUnsigned8(tlv.NewContextTag(1), trigger)
	if err := enc.EndContainer(); err != nil {
		t.Fatal(err)
	}
	return enc.Bytes()
}

func TestGeneralDiagnostics(t *testing.T) {
	var triggered []uint64
	deviceStore := store.NewMemDeviceStore()
	d, _, _ := startTestDevice(t,
		WithDeviceStore(deviceStore),
		WithTestEventTriggers(testEventKey, func(trigger uint64) bool {
			triggered = append(triggered, trigger)
			return trigger == 0x0001
		}))
	d.diagnostics.interfaces = func() ([]net.Interface, error) {
		return []net.Interface{
			{Index: 1, MTU: 65536, Name: "lo", HardwareAddr: nil, Flags: net.FlagUp | net.FlagLoopback},
			{Index: 2, MTU: 1500, Name: "eth0", HardwareAddr: net.HardwareAddr{2, 0, 0, 0, 0, 1}, Flags: net.FlagUp | net.FlagRunning},
		}, nil
	}
	sess := paseToDevice(t, d)

	if v, _ := readDiagnostic(t, sess, rebootCountAttributeID).Unsigned(); v != 1 {
		t.Fatalf("RebootCount = %d after the first boot, want 1", v)
	}
	if v, ok := readDiagnostic(t, sess, upTimeAttributeID).Unsigned(); !ok || 60 < v {
		t.Fatalf("UpTime = %d, want the few seconds since Start", v)
	}
	if v, _ := readDiagnostic(t, sess, testEventTriggersEnabledAttributeID).Bool(); !v {
		t.Fatal("TestEventTriggersEnabled is false with an enable key")
	}

	var names []string
	status, err := im.ReadListAttribute(sess, 0, GeneralDiagnosticsClusterID, networkInterfacesAttributeID, func(dec tlv.Decoder, _ tlv.Element) error {
		for dec.Next() {
			elem := dec.Element()
			if elem.Type().IsEndOfContainer() {
				break
			}
			if tag, _ := contextTagNumber(elem); tag == 0 {
				name, _ := elem.UTF8()
				names = append(names, name)
			}
			if elem.Type().IsContainer() {
				if err := skipTLVContainer(dec); err != nil {
					return err
				}
			}
		}
		return dec.Error()
	})
	if err != nil || status != nil || len(names) != 1 || names[0] != "eth0" {
		t.Fatalf("NetworkInterfaces = (%v, %+v, %v), want eth0 without the loopback", names, status, err)
	}

	for _, tc := range []struct {
		name    string
		key     []byte
		trigger uint64
		want    im.Status
	}{
		{"short key", testEventKey[:8], 1, im.StatusConstraintError},
		{"wrong key", bytes.Repeat([]byte{1}, testEventEnableKeyLength), 1, im.StatusUnsupportedAccess},
		{"unknown trigger", testEventKey, 2, im.StatusInvalidCommand},
		{"known trigger", testEventKey, 1, im.StatusSuccess},
	} {
		resp, err := im.Invoke(sess, 0, GeneralDiagnosticsClusterID, testEventTriggerCommandID, testEventTriggerFields(t, tc.key, tc.trigger))
		if err != nil {
			t.Fatal(err)
		}
		if resp.Status.IMStatus != uint8(tc.want) {
			t.Errorf("TestEventTrigger with %s: status %#x, want %#x", tc.name, resp.Status.IMStatus, uint8(tc.want))
		}
	}
	if len(triggered) != 2 {
		t.Fatalf("the handler ran for %v, want only the authorized triggers", triggered)
	}

	resp, err := im.Invoke(sess, 0, GeneralDiagnosticsClusterID, timeSnapshotCommandID, nil)
	if err != nil || !resp.IsSuccess() {
		t.Fatalf("TimeSnapshot = (%+v, %v)", resp, err)
	}
	if v, ok := resp.Field(1); !ok {
		t.Fatal("the TimeSnapshotResponse lacks PosixTimeMs")
	} else if ms, _ := v.Unsigned(); time.Since(time.UnixMilli(int64(ms))).Abs() > time.Minute { // nolint: gosec // a current time
		t.Fatalf("PosixTimeMs = %d, want about now", ms)
	}

	// Each start is a boot.
	if err := d.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := d.Start(); err != nil {
		t.Fatal(err)
	}
	if got := d.diagnostics.rebootCount; got != 2 {
		t.Fatalf("RebootCount = %d after the second boot, want 2", got)
	}
}

func TestWithTestEventTriggersChecksTheKey(t *testing.T) {
	for _, key := range [][]byte{nil, make([]byte, testEventEnableKeyLength), testEventKey[:15]} {
		if _, err := New(WithPasscode(testPasscode), WithTestEventTriggers(key, nil)); !errors.Is(err, errInvalidTestEventKey) {
			t.Errorf("WithTestEventTriggers(%x) = %v, want errInvalidTestEventKey", key, err)
		}
	}
	d, err := New(WithPasscode(testPasscode))
	if err != nil {
		t.Fatal(err)
	}
	if d.diagnostics.testEventKey != nil {
		t.Fatal("test event triggers are enabled by default")
	}
}
