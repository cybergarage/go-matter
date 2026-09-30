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
	"errors"
	"slices"
	"testing"

	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	"github.com/cybergarage/go-matter/matter/protocol/im"
)

func TestAddEndpoint(t *testing.T) {
	d, sess := startCommissioning(t)

	if _, err := d.AddEndpoint(0, OnOffLightDeviceType); !errors.Is(err, ErrEndpointReserved) {
		t.Fatalf("AddEndpoint(0) = %v, want ErrEndpointReserved", err)
	}
	if _, err := d.AddEndpoint(1); !errors.Is(err, ErrNoDeviceType) {
		t.Fatalf("AddEndpoint without a device type = %v, want ErrNoDeviceType", err)
	}
	ep, err := d.AddEndpoint(1, OnOffLightDeviceType)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.AddEndpoint(1, OnOffLightDeviceType); !errors.Is(err, ErrEndpointExists) {
		t.Fatalf("adding endpoint 1 twice = %v, want ErrEndpointExists", err)
	}
	on := true
	ep.HandleAttribute(0x0006, 0x0000, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		enc.PutBool(tag, on)
		return im.StatusSuccess
	})
	ep.HandleCommand(0x0006, 0x00, func(*im.CommandRequest) im.CommandResult {
		on = false
		return im.CommandStatus(im.StatusSuccess)
	})

	if got := readUintList(t, sess, 0, DescriptorClusterID, partsListAttributeID); !slices.Equal(got, []uint64{1}) {
		t.Fatalf("root PartsList = %v, want [1]", got)
	}
	if got := readUintList(t, sess, 1, DescriptorClusterID, serverListAttributeID); !slices.Equal(got, []uint64{0x0006, uint64(DescriptorClusterID)}) {
		t.Fatalf("endpoint 1 ServerList = %v", got)
	}
	if got := readUintList(t, sess, 1, DescriptorClusterID, partsListAttributeID); len(got) != 0 {
		t.Fatalf("endpoint 1 PartsList = %v, want none", got)
	}
	if v, err := im.ReadBoolAttribute(sess, 1, 0x0006, 0x0000); err != nil || !v {
		t.Fatalf("read OnOff = (%v, %v), want true", v, err)
	}
	// The commissioner's PASE session holds Administer, so it may operate.
	if resp, err := im.Invoke(sess, 1, 0x0006, 0x00, nil); err != nil || !resp.IsSuccess() {
		t.Fatalf("invoke Off = (%+v, %v)", resp, err)
	}
	if v, err := im.ReadBoolAttribute(sess, 1, 0x0006, 0x0000); err != nil || v {
		t.Fatalf("read OnOff after Off = (%v, %v), want false", v, err)
	}
	if ep.ID() != 1 {
		t.Fatalf("ID() = %d", ep.ID())
	}
}
