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
	"slices"
	"testing"

	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	"github.com/cybergarage/go-matter/matter/protocol/im"
	"github.com/cybergarage/go-matter/matter/protocol/session"
	"github.com/cybergarage/go-matter/matter/store"
)

// keySetFields encodes a KeySetWrite of key set id with epoch keys
// starting at starts.
func keySetFields(t *testing.T, id uint16, starts ...uint64) []byte {
	t.Helper()
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewContextTag(1))
	enc.BeginStructure(tlv.NewContextTag(0))
	enc.PutUnsigned2(tlv.NewContextTag(0), id)
	enc.PutUnsigned1(tlv.NewContextTag(1), 0)
	for i := range store.MaxEpochKeys {
		keyTag, startTag := tlv.NewContextTag(uint8(2+2*i)), tlv.NewContextTag(uint8(3+2*i)) // nolint: gosec // small
		if i < len(starts) {
			if err := enc.PutOctet(keyTag, bytes.Repeat([]byte{byte(i + 1)}, epochKeyLength)); err != nil {
				t.Fatal(err)
			}
			enc.PutUnsigned8(startTag, starts[i])
		} else {
			enc.PutNull(keyTag)
			enc.PutNull(startTag)
		}
	}
	if err := enc.EndContainer(); err != nil {
		t.Fatal(err)
	}
	if err := enc.EndContainer(); err != nil {
		t.Fatal(err)
	}
	return enc.Bytes()
}

func invokeGroupKeys(t *testing.T, sess session.SecureSession, cmd im.CommandID, fields []byte) *im.InvokeResponse {
	t.Helper()
	resp, err := im.Invoke(sess, 0, GroupKeyManagementClusterID, cmd, fields)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func keySetIDFields(t *testing.T, id uint16) []byte {
	t.Helper()
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewContextTag(1))
	enc.PutUnsigned2(tlv.NewContextTag(0), id)
	if err := enc.EndContainer(); err != nil {
		t.Fatal(err)
	}
	return enc.Bytes()
}

func writeGroupKeyMap(t *testing.T, sess session.SecureSession, entries ...[2]uint16) im.Status {
	t.Helper()
	resp, err := im.WriteAttribute(sess, 0, GroupKeyManagementClusterID, groupKeyMapAttributeID, func(enc tlv.Encoder) error {
		enc.BeginArray(tlv.NewContextTag(2))
		for _, e := range entries {
			enc.BeginStructure(tlv.NewAnonymousTag())
			enc.PutUnsigned2(tlv.NewContextTag(1), e[0])
			enc.PutUnsigned2(tlv.NewContextTag(2), e[1])
			if err := enc.EndContainer(); err != nil {
				return err
			}
		}
		return enc.EndContainer()
	})
	if err != nil {
		t.Fatal(err)
	}
	return im.Status(resp.Status.IMStatus)
}

func TestGroupKeyManagement(t *testing.T) {
	d, adv, _, _, admin := commissionedDevice(t)
	waitOperational(t, adv, 1)

	// Key sets: not the IPK, epoch keys in order, MaxGroupKeysPerFabric
	// with the IPK.
	for _, tc := range []struct {
		name   string
		fields []byte
		want   im.Status
	}{
		{"the IPK", keySetFields(t, 0, 1), im.StatusInvalidCommand},
		{"no epoch key", keySetFields(t, 1), im.StatusInvalidCommand},
		{"epoch keys out of order", keySetFields(t, 1, 5, 3), im.StatusInvalidCommand},
		{"key set 1", keySetFields(t, 1, 1, 2), im.StatusSuccess},
		{"key set 2", keySetFields(t, 2, 1), im.StatusSuccess},
		{"key set 3", keySetFields(t, 3, 1), im.StatusResourceExhausted},
	} {
		if got := invokeGroupKeys(t, admin, keySetWriteCommandID, tc.fields).Status.IMStatus; got != uint8(tc.want) {
			t.Errorf("KeySetWrite of %s: status %#x, want %#x", tc.name, got, uint8(tc.want))
		}
	}
	resp := invokeGroupKeys(t, admin, keySetReadCommandID, keySetIDFields(t, 1))
	if !resp.IsSuccess() || resp.Payload == nil {
		t.Fatalf("KeySetRead(1) = %+v", resp)
	}
	if got := invokeGroupKeys(t, admin, keySetReadCommandID, keySetIDFields(t, 9)).Status.IMStatus; got != uint8(im.StatusNotFound) {
		t.Fatalf("KeySetRead(9): status %#x, want NOT_FOUND", got)
	}
	rec, err := d.store.LoadGroupKeys(1)
	if err != nil || len(rec.KeySets) != 3 || len(rec.KeySets[1].EpochKeys) != 2 {
		t.Fatalf("the stored key sets are (%+v, %v)", rec.KeySets, err)
	}

	// The key map: a group to a key set other than the IPK.
	if s := writeGroupKeyMap(t, admin, [2]uint16{1, 0}); s != im.StatusConstraintError {
		t.Fatalf("mapping a group to the IPK: status %#x, want CONSTRAINT_ERROR", uint8(s))
	}
	if s := writeGroupKeyMap(t, admin, [2]uint16{1, 1}, [2]uint16{2, 2}); s != im.StatusSuccess {
		t.Fatalf("write GroupKeyMap: status %#x", uint8(s))
	}

	// An endpoint joins only a group with a key.
	ep, err := d.AddEndpoint(1, OnOffLightDeviceType)
	if err != nil {
		t.Fatal(err)
	}
	if s := ep.JoinGroup(1, 7, ""); s != im.StatusUnsupportedAccess {
		t.Fatalf("JoinGroup(7) without a key: status %#x, want UNSUPPORTED_ACCESS", uint8(s))
	}
	if s := ep.JoinGroup(1, 1, "Kitchen"); s != im.StatusSuccess {
		t.Fatalf("JoinGroup(1): status %#x", uint8(s))
	}
	if groups := ep.Groups(1); len(groups) != 1 || groups[0].GroupID != 1 || groups[0].Name != "Kitchen" {
		t.Fatalf("Groups = %+v", groups)
	}
	var tableGroups []uint64
	status, err := im.ReadListAttribute(admin, 0, GroupKeyManagementClusterID, groupTableAttributeID, func(dec tlv.Decoder, _ tlv.Element) error {
		for dec.Next() {
			elem := dec.Element()
			if elem.Type().IsEndOfContainer() {
				break
			}
			if tag, _ := contextTagNumber(elem); tag == 1 {
				v, _ := elem.Unsigned()
				tableGroups = append(tableGroups, v)
			}
			if elem.Type().IsContainer() {
				if err := skipTLVContainer(dec); err != nil {
					return err
				}
			}
		}
		return dec.Error()
	})
	if err != nil || status != nil || !slices.Equal(tableGroups, []uint64{1}) {
		t.Fatalf("GroupTable = (%v, %+v, %v), want group 1", tableGroups, status, err)
	}

	// Removing a key set unmaps its groups.
	if got := invokeGroupKeys(t, admin, keySetRemoveCommandID, keySetIDFields(t, 0)).Status.IMStatus; got != uint8(im.StatusInvalidCommand) {
		t.Fatalf("KeySetRemove of the IPK: status %#x, want INVALID_COMMAND", got)
	}
	if resp := invokeGroupKeys(t, admin, keySetRemoveCommandID, keySetIDFields(t, 2)); !resp.IsSuccess() {
		t.Fatalf("KeySetRemove(2) = %+v", resp)
	}
	resp = invokeGroupKeys(t, admin, keySetReadAllIndicesCommandID, nil)
	if !resp.IsSuccess() {
		t.Fatalf("KeySetReadAllIndices = %+v", resp)
	}
	if rec, _ := d.store.LoadGroupKeys(1); len(rec.KeySets) != 2 || len(rec.KeyMap) != 1 || rec.KeyMap[0].GroupID != 1 {
		t.Fatalf("after KeySetRemove(2) the store holds %+v", rec)
	}

	if s := ep.LeaveGroup(1, 1); s != im.StatusSuccess {
		t.Fatalf("LeaveGroup(1): status %#x", uint8(s))
	}
	if rec, _ := d.store.LoadGroupKeys(1); len(rec.Groups) != 0 {
		t.Fatalf("the group table still holds %+v", rec.Groups)
	}
}
