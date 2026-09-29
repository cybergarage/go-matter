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
	"testing"

	"github.com/cybergarage/go-matter/matter/store"
)

func TestSubjectMatches(t *testing.T) {
	const node = 0x0000000000001234
	cats := []uint32{0xABCD0002}
	for _, tc := range []struct {
		subjects []uint64
		want     bool
	}{
		{nil, true},
		{[]uint64{node}, true},
		{[]uint64{node + 1}, false},
		{[]uint64{0xFFFFFFFD_ABCD0001}, true},  // an older CAT version
		{[]uint64{0xFFFFFFFD_ABCD0002}, true},  // the same version
		{[]uint64{0xFFFFFFFD_ABCD0003}, false}, // a newer one
		{[]uint64{0xFFFFFFFD_ABCE0001}, false}, // another CAT
		{[]uint64{node + 1, 0xFFFFFFFD_ABCD0001}, true},
	} {
		if got := subjectMatches(tc.subjects, node, cats); got != tc.want {
			t.Errorf("subjectMatches(%X) = %v, want %v", tc.subjects, got, tc.want)
		}
	}
}

func TestTargetMatches(t *testing.T) {
	cluster := uint32(0x0006)
	otherCluster := uint32(0x0008)
	endpoint := uint16(1)
	deviceType := uint32(0x0100)
	for _, tc := range []struct {
		name    string
		targets []store.ACLTarget
		want    bool
	}{
		{"none", nil, true},
		{"cluster", []store.ACLTarget{{Cluster: &cluster, Endpoint: nil, DeviceType: nil}}, true},
		{"other cluster", []store.ACLTarget{{Cluster: &otherCluster, Endpoint: nil, DeviceType: nil}}, false},
		{"endpoint", []store.ACLTarget{{Cluster: nil, Endpoint: &endpoint, DeviceType: nil}}, true},
		{"cluster on endpoint", []store.ACLTarget{{Cluster: &cluster, Endpoint: &endpoint, DeviceType: nil}}, true},
		{"device type", []store.ACLTarget{{Cluster: nil, Endpoint: nil, DeviceType: &deviceType}}, false},
	} {
		if got := targetMatches(tc.targets, 1, 0x0006); got != tc.want {
			t.Errorf("targetMatches(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}
}
