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
	"sync/atomic"
	"testing"

	"github.com/cybergarage/go-matter/matter/encoding/message"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
)

func TestServerWrite(t *testing.T) {
	srv := testServer()
	var label string
	var appended []uint64
	srv.HandleAttributeWrite(0, 0x0028, 0x0005, func(req *AttributeWriteRequest) Status {
		_, elem, err := req.Decoder()
		if err != nil {
			return StatusInvalidDataType
		}
		v, ok := elem.UTF8()
		if !ok {
			return StatusInvalidDataType
		}
		label = v
		return StatusSuccess
	})
	// A list attribute written as a whole: the handler decodes the array.
	srv.HandleAttributeWrite(0, 0x001F, 0x0000, func(req *AttributeWriteRequest) Status {
		dec, elem, err := req.Decoder()
		if err != nil || !elem.Type().IsArray() {
			return StatusInvalidDataType
		}
		appended = nil
		for dec.Next() {
			item := dec.Element()
			if item.Type().IsEndOfContainer() {
				break
			}
			if item.Type().IsStructure() {
				for dec.Next() {
					field := dec.Element()
					if field.Type().IsEndOfContainer() {
						break
					}
					if v, ok := field.Unsigned(); ok {
						appended = append(appended, v)
					}
				}
			}
		}
		return StatusSuccess
	}, WithPrivilege(PrivilegeAdminister))
	srv.SetAccessChecker(func(req AccessRequest) bool {
		return PrivilegeManage.Grants(req.Privilege)
	})
	client := startServer(t, srv)

	resp, err := WriteAttribute(client, 0, 0x0028, 0x0005, func(enc tlv.Encoder) error {
		return enc.PutUTF8(tlv.NewContextTag(2), "kitchen")
	})
	if err != nil || !resp.IsSuccess() || label != "kitchen" {
		t.Fatalf("WriteAttribute(NodeLabel) = (%+v, %v), label %q", resp, err, label)
	}

	for _, tc := range []struct {
		name      string
		endpoint  EndpointID
		cluster   ClusterID
		attribute AttributeID
		want      Status
	}{
		{"read-only", 0, 0x0030, 0x0000, StatusUnsupportedWrite},
		{"unknown attribute", 0, 0x0028, 0x0099, StatusUnsupportedAttribute},
		{"unknown cluster", 0, 0x0999, 0x0000, StatusUnsupportedCluster},
		{"needing Administer", 0, 0x001F, 0x0000, StatusUnsupportedAccess},
	} {
		resp, err := WriteAttribute(client, tc.endpoint, tc.cluster, tc.attribute, func(enc tlv.Encoder) error {
			enc.BeginArray(tlv.NewContextTag(2))
			enc.BeginStructure(tlv.NewAnonymousTag())
			enc.PutUnsigned1(tlv.NewContextTag(1), 5)
			if err := enc.EndContainer(); err != nil {
				return err
			}
			return enc.EndContainer()
		})
		if err != nil {
			t.Fatal(err)
		}
		if resp.Status.IMStatus != uint8(tc.want) {
			t.Errorf("write %s: status %+v, want %#x", tc.name, resp.Status, uint8(tc.want))
		}
	}

	srv.SetAccessChecker(nil)
	resp, err = WriteAttribute(client, 0, 0x001F, 0x0000, func(enc tlv.Encoder) error {
		enc.BeginArray(tlv.NewContextTag(2))
		for _, v := range []uint8{5, 3} {
			enc.BeginStructure(tlv.NewAnonymousTag())
			enc.PutUnsigned1(tlv.NewContextTag(1), v)
			if err := enc.EndContainer(); err != nil {
				return err
			}
		}
		return enc.EndContainer()
	})
	if err != nil || !resp.IsSuccess() {
		t.Fatalf("WriteAttribute(list) = (%+v, %v)", resp, err)
	}
	if len(appended) != 2 || appended[0] != 5 || appended[1] != 3 {
		t.Fatalf("the list handler decoded %v, want [5 3]", appended)
	}
}

// buildChunkedListWrite encodes a WriteRequest which replaces a list
// attribute by an empty list and appends items to it, as the SDK writes
// lists, followed by a write of other.
func buildChunkedListWrite(list AttributePath, items []uint8, other AttributePath) []byte {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	enc.PutBool(tlv.NewContextTag(0), false)
	enc.PutBool(tlv.NewContextTag(1), false)
	enc.BeginArray(tlv.NewContextTag(2))
	ib := func(p AttributePath, appendItem bool, data func()) {
		enc.BeginStructure(tlv.NewAnonymousTag())
		enc.BeginList(tlv.NewContextTag(1))
		enc.PutUnsigned2(tlv.NewContextTag(2), uint16(p.Endpoint))
		_ = enc.PutUnsigned(tlv.NewContextTag(3), uint64(p.Cluster))
		_ = enc.PutUnsigned(tlv.NewContextTag(4), uint64(p.Attribute))
		if appendItem {
			enc.PutNull(tlv.NewContextTag(5))
		}
		_ = enc.EndContainer()
		data()
		_ = enc.EndContainer()
	}
	ib(list, false, func() {
		enc.BeginArray(tlv.NewContextTag(2))
		_ = enc.EndContainer()
	})
	for _, v := range items {
		ib(list, true, func() { enc.PutUnsigned1(tlv.NewContextTag(2), v) })
	}
	ib(other, false, func() { enc.PutUnsigned1(tlv.NewContextTag(2), 1) })
	_ = enc.EndContainer()
	enc.PutUnsigned1(tlv.NewContextTag(interactionModelRevisionTag), interactionModelRevision)
	_ = enc.EndContainer()
	return enc.Bytes()
}

// TestServerWriteChunkedListKeepsAccess writes a list in chunks whose
// first chunk revokes the writer's access, as replacing an ACL by an
// empty one does: the rest of the list is still written, since access is
// checked once per path and request, but another path is refused.
func TestServerWriteChunkedListKeepsAccess(t *testing.T) {
	srv := testServer()
	var allowed atomic.Bool
	allowed.Store(true)
	var list []uint64
	listPath := AttributePath{Endpoint: 0, Cluster: 0x001F, Attribute: 0x0000}
	otherPath := AttributePath{Endpoint: 0, Cluster: 0x001F, Attribute: 0x0001}
	srv.HandleAttributeWrite(listPath.Endpoint, listPath.Cluster, listPath.Attribute, func(req *AttributeWriteRequest) Status {
		_, elem, err := req.Decoder()
		if err != nil {
			return StatusInvalidDataType
		}
		if !req.Append {
			list = nil
			allowed.Store(false) // the empty list grants nobody
			return StatusSuccess
		}
		v, _ := elem.Unsigned()
		list = append(list, v)
		return StatusSuccess
	})
	srv.HandleAttributeWrite(otherPath.Endpoint, otherPath.Cluster, otherPath.Attribute, func(*AttributeWriteRequest) Status {
		return StatusSuccess
	})
	srv.SetAccessChecker(func(AccessRequest) bool { return allowed.Load() })
	client := startServer(t, srv)

	exchange := message.NewFirstExchangeID()
	if err := transmitOnExchange(client, message.WriteRequestMessage, exchange, buildChunkedListWrite(listPath, []uint8{5, 3}, otherPath)); err != nil {
		t.Fatal(err)
	}
	_, body := receiveIM(t, client, message.WriteResponseMessage)
	var statuses []uint64
	dec := tlv.NewDecoderWithBytes(body)
	for dec.Next() {
		elem := dec.Element()
		// The Status of each StatusIB is its context tag 0 inside tag 1.
		if ct, ok := elem.Tag().(tlv.ContextTag); ok && ct.ContextNumber() == 1 && elem.Type().IsStructure() {
			dec.Next()
			v, _ := dec.Element().Unsigned()
			statuses = append(statuses, v)
		}
	}
	want := []uint64{uint64(StatusSuccess), uint64(StatusSuccess), uint64(StatusSuccess), uint64(StatusUnsupportedAccess)}
	if !slices.Equal(statuses, want) {
		t.Fatalf("write statuses = %#x, want %#x", statuses, want)
	}
	if !slices.Equal(list, []uint64{5, 3}) {
		t.Fatalf("the list is %v, want [5 3]", list)
	}
}
