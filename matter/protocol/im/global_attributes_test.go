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

package im

import (
	"slices"
	"testing"

	"github.com/cybergarage/go-matter/matter/encoding/tlv"
)

func readIDList(t *testing.T, client SecureSession, endpoint EndpointID, cluster ClusterID, attr AttributeID) []uint64 {
	t.Helper()
	var ids []uint64
	status, err := ReadListAttribute(client, endpoint, cluster, attr, func(_ tlv.Decoder, item tlv.Element) error {
		v, _ := item.Unsigned()
		ids = append(ids, v)
		return nil
	})
	if err != nil || status != nil {
		t.Fatalf("read 0x%04X: (%+v, %v)", attr, status, err)
	}
	return ids
}

func TestServerGlobalAttributes(t *testing.T) {
	srv := testServer()
	srv.HandleCommand(0, 0x0030, 0x02, func(*CommandRequest) CommandResult {
		return CommandStatus(StatusSuccess)
	}, WithResponseCommand(0x03))
	srv.HandleCommand(0, 0x0030, 0x00, func(*CommandRequest) CommandResult {
		return CommandStatus(StatusSuccess)
	}, WithResponseCommand(0x01))
	client := startServer(t, srv)

	if got, want := readIDList(t, client, 0, 0x0030, AcceptedCommandListAttributeID), []uint64{0x00, 0x02, 0x04}; !slices.Equal(got, want) {
		t.Errorf("AcceptedCommandList = %v, want %v", got, want)
	}
	if got, want := readIDList(t, client, 0, 0x0030, GeneratedCommandListAttributeID), []uint64{0x01, 0x03}; !slices.Equal(got, want) {
		t.Errorf("GeneratedCommandList = %v, want %v", got, want)
	}
	if got, want := readIDList(t, client, 0, 0x0030, AttributeListAttributeID), []uint64{0x0000, 0x0004, 0xFFF8, 0xFFF9, 0xFFFB}; !slices.Equal(got, want) {
		t.Errorf("AttributeList = %v, want %v", got, want)
	}
	if got, want := srv.Endpoints(), []EndpointID{0, 1}; !slices.Equal(got, want) {
		t.Errorf("Endpoints() = %v, want %v", got, want)
	}
	if got, want := srv.Clusters(0), []ClusterID{0x0028, 0x0030, 0x003E}; !slices.Equal(got, want) {
		t.Errorf("Clusters(0) = %v, want %v", got, want)
	}
}
