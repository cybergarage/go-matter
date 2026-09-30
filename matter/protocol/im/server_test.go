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
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/cybergarage/go-matter/matter/encoding/message"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	"github.com/cybergarage/go-matter/matter/protocol/session"
	"github.com/cybergarage/go-matter/matter/types"
)

type serverTestKeys struct{}

func (serverTestKeys) I2RKey() []byte                      { return bytes.Repeat([]byte{1}, 16) }
func (serverTestKeys) R2IKey() []byte                      { return bytes.Repeat([]byte{2}, 16) }
func (serverTestKeys) InitiatorSessionID() types.SessionID { return 11 }
func (serverTestKeys) ResponderSessionID() types.SessionID { return 22 }
func (serverTestKeys) LocalNodeID() types.NodeID           { return 0 }
func (serverTestKeys) PeerNodeID() types.NodeID            { return 0 }
func (serverTestKeys) AttestationChallenge() []byte        { return nil }

// chanTransport is one end of an in-memory pipe which ends with closed.
type chanTransport struct {
	in     <-chan []byte
	out    chan<- []byte
	closed <-chan struct{}
}

var errClosed = errors.New("closed")

func (c *chanTransport) Transmit(_ context.Context, b []byte) error {
	select {
	case c.out <- bytes.Clone(b):
		return nil
	case <-c.closed:
		return errClosed
	}
}

func (c *chanTransport) Receive(ctx context.Context) ([]byte, error) {
	select {
	case b := <-c.in:
		return b, nil
	case <-c.closed:
		return nil, errClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// startServer serves srv on the responder side of a session pair, and
// returns the initiator side.
func startServer(t *testing.T, srv *Server) SecureSession {
	t.Helper()
	a2b := make(chan []byte, 16)
	b2a := make(chan []byte, 16)
	closed := make(chan struct{})
	client := session.NewSecureSession(&chanTransport{in: b2a, out: a2b, closed: closed}, serverTestKeys{})
	device := session.NewSecureSession(&chanTransport{in: a2b, out: b2a, closed: closed}, serverTestKeys{}, session.WithRole(session.RoleResponder))
	done := make(chan error, 1)
	go func() { done <- srv.Serve(device) }()
	t.Cleanup(func() {
		close(closed)
		select {
		case err := <-done:
			if !errors.Is(err, errClosed) {
				t.Errorf("Serve() = %v, want the transport's error", err)
			}
		case <-time.After(time.Second):
			t.Error("Serve() did not return after the transport closed")
		}
	})
	return client
}

func testServer() *Server {
	srv := NewServer()
	srv.HandleCommand(0, 0x0030, 0x00, func(req *CommandRequest) CommandResult {
		expiry, _ := req.Fields[0].Unsigned()
		enc := tlv.NewEncoder()
		enc.BeginStructure(tlv.NewContextTag(1))
		enc.PutUnsigned1(tlv.NewContextTag(0), 0)
		enc.PutUnsigned2(tlv.NewContextTag(1), uint16(expiry))
		_ = enc.EndContainer()
		return CommandResponse(0x01, enc.Bytes())
	})
	srv.HandleCommand(0, 0x0030, 0x04, func(*CommandRequest) CommandResult {
		return CommandClusterStatus(StatusFailure, 3)
	})
	srv.HandleCommand(0, 0x003E, 0x0B, func(*CommandRequest) CommandResult {
		return CommandStatus(StatusSuccess)
	})
	srv.HandleAttribute(0, 0x0030, 0x0004, func(enc tlv.Encoder, tag tlv.Tag) Status {
		enc.PutBool(tag, true)
		return StatusSuccess
	})
	srv.HandleAttribute(0, 0x0030, 0x0000, func(enc tlv.Encoder, tag tlv.Tag) Status {
		enc.PutUnsigned1(tag, 7)
		return StatusSuccess
	})
	srv.HandleAttribute(0, 0x0028, 0x0002, func(enc tlv.Encoder, tag tlv.Tag) Status {
		return StatusUnsupportedRead
	})
	srv.HandleAttribute(1, 0x0006, 0x0000, func(enc tlv.Encoder, tag tlv.Tag) Status {
		enc.PutBool(tag, false)
		return StatusSuccess
	})
	return srv
}

func armFailSafeFields(expiry uint16) []byte {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewContextTag(1))
	enc.PutUnsigned2(tlv.NewContextTag(0), expiry)
	_ = enc.PutUnsigned(tlv.NewContextTag(1), 0)
	_ = enc.EndContainer()
	return enc.Bytes()
}

func TestServerInvoke(t *testing.T) {
	client := startServer(t, testServer())

	resp, err := Invoke(client, 0, 0x0030, 0x00, armFailSafeFields(60))
	if err != nil {
		t.Fatalf("Invoke(ArmFailSafe) error = %v", err)
	}
	if !resp.IsSuccess() {
		t.Fatalf("Invoke(ArmFailSafe) status = %+v", resp.Status)
	}
	if v, ok := resp.Field(1); !ok {
		t.Fatal("the response lacks field 1")
	} else if n, _ := v.Unsigned(); n != 60 {
		t.Fatalf("response field 1 = %d, want the 60 the handler echoed", n)
	}

	resp, err = Invoke(client, 0, 0x0030, 0x04, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status.IMStatus != uint8(StatusFailure) || resp.Status.ClusterStatus != 3 {
		t.Fatalf("status-only command: status = %+v, want Failure with cluster status 3", resp.Status)
	}

	resp, err = Invoke(client, 0, 0x003E, 0x0B, nil)
	if err != nil || !resp.IsSuccess() || resp.Payload != nil {
		t.Fatalf("success without a response command: (%+v, %v)", resp, err)
	}
}

func TestServerInvokeUnknownPaths(t *testing.T) {
	client := startServer(t, testServer())
	for _, tc := range []struct {
		endpoint EndpointID
		cluster  ClusterID
		command  CommandID
		want     Status
	}{
		{0, 0x0030, 0x7F, StatusUnsupportedCommand},
		{0, 0x0999, 0x00, StatusUnsupportedCluster},
		{9, 0x0030, 0x00, StatusUnsupportedEndpoint},
	} {
		resp, err := Invoke(client, tc.endpoint, tc.cluster, tc.command, nil)
		if err != nil {
			t.Fatal(err)
		}
		if resp.Status.IMStatus != uint8(tc.want) {
			t.Errorf("Invoke(%d, %#x, %#x) status = %#x, want %#x", tc.endpoint, tc.cluster, tc.command, resp.Status.IMStatus, uint8(tc.want))
		}
	}
}

func TestServerRead(t *testing.T) {
	client := startServer(t, testServer())

	v, err := ReadBoolAttribute(client, 0, 0x0030, 0x0004)
	if err != nil || !v {
		t.Fatalf("ReadBoolAttribute() = (%v, %v), want (true, nil)", v, err)
	}

	for _, tc := range []struct {
		endpoint  EndpointID
		cluster   ClusterID
		attribute AttributeID
		want      Status
	}{
		{0, 0x0030, 0x0099, StatusUnsupportedAttribute},
		{0, 0x0999, 0x0000, StatusUnsupportedCluster},
		{9, 0x0030, 0x0000, StatusUnsupportedEndpoint},
		{0, 0x0028, 0x0002, StatusUnsupportedRead},
	} {
		resp, err := ReadAttribute(client, tc.endpoint, tc.cluster, tc.attribute)
		if err != nil {
			t.Fatal(err)
		}
		if resp.Status == nil || resp.Status.IMStatus != uint8(tc.want) {
			t.Errorf("ReadAttribute(%d, %#x, %#x) status = %+v, want %#x", tc.endpoint, tc.cluster, tc.attribute, resp.Status, uint8(tc.want))
		}
	}
}

// readRaw sends a ReadRequest for paths, where a negative value is a
// wildcard, and returns the ReportData body.
func readRaw(t *testing.T, client SecureSession, paths ...[3]int64) []byte {
	t.Helper()
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	enc.BeginArray(tlv.NewContextTag(0))
	for _, p := range paths {
		enc.BeginList(tlv.NewAnonymousTag())
		for i, v := range p {
			if 0 <= v {
				_ = enc.PutUnsigned(tlv.NewContextTag(uint8(2+i)), uint64(v))
			}
		}
		_ = enc.EndContainer()
	}
	_ = enc.EndContainer()
	enc.PutBool(tlv.NewContextTag(3), true)
	enc.PutUnsigned1(tlv.NewContextTag(interactionModelRevisionTag), interactionModelRevision)
	_ = enc.EndContainer()

	hdr, exchange, err := buildIMProtocolHeader(message.ReadRequestMessage)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Transmit(append(hdr, enc.Bytes()...)); err != nil {
		t.Fatal(err)
	}
	raw, err := receiveExchangeResponse(client, exchange)
	if err != nil {
		t.Fatal(err)
	}
	protHdr, _ := message.NewProtocolHeaderFromBytes(raw)
	if !protHdr.Opcode().IsReportDataMessage() {
		t.Fatalf("answered with opcode %#x, want ReportData", uint8(protHdr.Opcode()))
	}
	hdrBytes, _ := protHdr.Bytes()
	return raw[len(hdrBytes):]
}

// reportedPaths lists the (endpoint, cluster, attribute) of each
// AttributeDataIB in a ReportData body.
func reportedPaths(t *testing.T, body []byte) [][3]uint64 {
	t.Helper()
	dec := tlv.NewDecoderWithBytes(body)
	var paths [][3]uint64
	var cur [3]uint64
	inPath := false
	for dec.Next() {
		elem := dec.Element()
		tag, ok := contextNumber(elem)
		switch {
		case ok && tag == 1 && elem.Type().IsList():
			inPath = true
			cur = [3]uint64{}
		case inPath && elem.Type().IsEndOfContainer():
			inPath = false
			paths = append(paths, cur)
		case inPath && ok && 2 <= tag && tag <= 4:
			v, _ := elem.Unsigned()
			cur[tag-2] = v
		}
	}
	if err := dec.Error(); err != nil {
		t.Fatal(err)
	}
	return paths
}

func TestServerReadWildcards(t *testing.T) {
	client := startServer(t, testServer())

	// Every attribute of cluster 0x0030 on any endpoint.
	got := reportedPaths(t, readRaw(t, client, [3]int64{-1, 0x0030, -1}))
	want := [][3]uint64{{0, 0x0030, 0x0000}, {0, 0x0030, 0x0004}, {0, 0x0030, 0xFFF8}, {0, 0x0030, 0xFFF9}, {0, 0x0030, 0xFFFB}}
	if !slices.Equal(got, want) {
		t.Fatalf("wildcard read reported %v, want %v", got, want)
	}

	// A wildcard which matches nothing reports nothing, and two paths in
	// one request are both answered.
	got = reportedPaths(t, readRaw(t, client, [3]int64{-1, 0x0999, -1}, [3]int64{1, 0x0006, 0}))
	if len(got) != 1 || got[0] != [3]uint64{1, 0x0006, 0} {
		t.Fatalf("read reported %v, want only the OnOff attribute", got)
	}
}

func TestServerAnswersUnsupportedInteractions(t *testing.T) {
	client := startServer(t, testServer())
	hdr, exchange, err := buildIMProtocolHeader(message.WriteRequestMessage)
	if err != nil {
		t.Fatal(err)
	}
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	_ = enc.EndContainer()
	if err := client.Transmit(append(hdr, enc.Bytes()...)); err != nil {
		t.Fatal(err)
	}
	raw, err := receiveExchangeResponse(client, exchange)
	if err != nil {
		t.Fatal(err)
	}
	protHdr, _ := message.NewProtocolHeaderFromBytes(raw)
	if !protHdr.Opcode().IsStatusResponseMessage() {
		t.Fatalf("answered a Write with opcode %#x, want StatusResponse", uint8(protHdr.Opcode()))
	}
	hdrBytes, _ := protHdr.Bytes()
	status, err := parseStatusResponseMessage(raw[len(hdrBytes):])
	if err != nil {
		t.Fatal(err)
	}
	if status.IMStatus != uint8(StatusInvalidAction) {
		t.Fatalf("Write answered with status %#x, want InvalidAction", status.IMStatus)
	}

	// A malformed request is answered with InvalidAction, and the server
	// keeps serving.
	hdr, exchange, _ = buildIMProtocolHeader(message.InvokeRequestMessage)
	if err := client.Transmit(append(hdr, 0x15, 0x18)); err != nil {
		t.Fatal(err)
	}
	if _, err := receiveExchangeResponse(client, exchange); err != nil {
		t.Fatal(err)
	}
	if v, err := ReadBoolAttribute(client, 0, 0x0030, 0x0004); err != nil || !v {
		t.Fatalf("after a malformed request: ReadBoolAttribute() = (%v, %v)", v, err)
	}
}
