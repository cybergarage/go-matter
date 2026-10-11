// Copyright (C) 2026 The go-matter Authors. Licensed under the Apache License, Version 2.0.

package tui

import (
	"errors"
	"strings"
	"testing"

	"github.com/cybergarage/go-matter/matter"
	"github.com/cybergarage/go-matter/matter/encoding/message"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	"github.com/cybergarage/go-matter/matter/protocol/im"
)

// Replay encoded, already-decrypted IM bytes; no transport or physical node.
type encodedReadSession struct {
	im.SecureSession
	payload, response []byte
}

func (s *encodedReadSession) Transmit(request []byte) error {
	h, err := message.NewProtocolHeaderFromBytes(request)
	if err != nil {
		return err
	}
	header, err := message.NewProtocolHeader(message.WithHeaderExchangeID(h.ExchangeID()), message.WithHeaderProtocolID(message.InteractionModel), message.WithHeaderOpcode(message.ReportDataMessage)).Bytes()
	if err != nil {
		return err
	}
	s.response = header
	s.response = append(s.response, s.payload...)
	return nil
}
func (s *encodedReadSession) Receive() ([]byte, error) {
	if s.response == nil {
		return nil, errors.New("no queued fixture")
	}
	raw := s.response
	s.response = nil
	return raw, nil
}

type encodedReadNode struct {
	matter.Node
	session *encodedReadSession
}

func (n encodedReadNode) ReadAttribute(ep im.EndpointID, cl im.ClusterID, attr im.AttributeID) (*im.ReadResponse, error) {
	return im.ReadAttribute(n.session, ep, cl, attr)
}

func (n encodedReadNode) ReadValueAttribute(ep im.EndpointID, cl im.ClusterID, attr im.AttributeID) (*im.ValueReadResponse, error) {
	return im.ReadValueAttribute(n.session, ep, cl, attr)
}

func capabilityPayload(t *testing.T, cluster uint32, attribute uint32) []byte {
	t.Helper()
	e := tlv.NewEncoder()
	e.BeginStructure(tlv.NewAnonymousTag())
	e.BeginArray(tlv.NewContextTag(1))
	e.BeginStructure(tlv.NewAnonymousTag())
	e.BeginStructure(tlv.NewContextTag(1)) // AttributeDataIB
	e.BeginList(tlv.NewContextTag(1))      // Exact fixture path.
	e.PutUnsigned2(tlv.NewContextTag(2), 1)
	e.PutUnsigned4(tlv.NewContextTag(3), cluster)
	e.PutUnsigned4(tlv.NewContextTag(4), attribute)
	if err := e.EndContainer(); err != nil {
		t.Fatal(err)
	}
	e.BeginStructure(tlv.NewContextTag(2)) // CapabilityMinimaStruct-shaped Data.
	e.PutUnsigned2(tlv.NewContextTag(0), 1)
	e.PutUnsigned2(tlv.NewContextTag(1), 2)
	e.PutUnsigned2(tlv.NewContextTag(2), 7) // SimultaneousInvocationsSupported.
	for range 4 {
		if err := e.EndContainer(); err != nil {
			t.Fatal(err)
		}
	}
	e.PutUnsigned1(tlv.NewContextTag(0xFF), 1)
	if err := e.EndContainer(); err != nil {
		t.Fatal(err)
	}
	return e.Bytes()
}

func TestEncodedStructureBecomesCompleteObservation(t *testing.T) {
	node := encodedReadNode{session: &encodedReadSession{payload: capabilityPayload(t, 0x28, 19)}}
	result, err := readNode(node, Path{Endpoint: 1, Cluster: 0x28, Attribute: 19})
	if err != nil || !strings.Contains(result.Message, "FRESH READ") || !strings.Contains(result.Message, "SimultaneousInvocationsSupported") || !strings.Contains(result.Message, "Structure") {
		t.Fatalf("container misrepresented: result=%+v error=%v", result, err)
	}
}

func TestEncodedMalformedStructureNeverFresh(t *testing.T) {
	for _, payload := range [][]byte{{0x15}, {0x15, 0x36, 1, 0x15, 0x35, 1, 0x35, 2, 0x25, 2, 7}} {
		n := encodedReadNode{session: &encodedReadSession{payload: payload}}
		r, err := readNode(n, Path{Endpoint: 1, Cluster: 0x28, Attribute: 19})
		if err == nil || r.Message != "" {
			t.Fatalf("partial became fresh: %+v %v", r, err)
		}
	}
}

func TestEncodedUnknownStructureRetainsTagsAndTypes(t *testing.T) {
	n := encodedReadNode{session: &encodedReadSession{payload: capabilityPayload(t, 0xdead, 0x1234)}}
	r, err := readNode(n, Path{Endpoint: 1, Cluster: 0xdead, Attribute: 0x1234})
	if err != nil || !strings.Contains(r.Message, "FRESH READ") || !strings.Contains(r.Message, "Unknown field Context(2) (UnsignedInt2)=7") || strings.Contains(r.Message, "SimultaneousInvocationsSupported") {
		t.Fatalf("unknown structure misrepresented: %+v %v", r, err)
	}
}
func TestEncodedStatusNeverFresh(t *testing.T) {
	e := tlv.NewEncoder()
	e.BeginStructure(tlv.NewAnonymousTag())
	e.BeginArray(tlv.NewContextTag(1))
	e.BeginStructure(tlv.NewAnonymousTag())
	e.BeginStructure(tlv.NewContextTag(0))
	e.BeginList(tlv.NewContextTag(0))
	e.PutUnsigned2(tlv.NewContextTag(2), 1)
	e.PutUnsigned4(tlv.NewContextTag(3), 0x28)
	e.PutUnsigned4(tlv.NewContextTag(4), 19)
	if err := e.EndContainer(); err != nil {
		t.Fatal(err)
	}
	e.BeginStructure(tlv.NewContextTag(1))
	e.PutUnsigned1(tlv.NewContextTag(0), uint8(im.StatusUnsupportedAccess))
	for range 4 {
		if err := e.EndContainer(); err != nil {
			t.Fatal(err)
		}
	}
	e.PutUnsigned1(tlv.NewContextTag(0xff), 12)
	if err := e.EndContainer(); err != nil {
		t.Fatal(err)
	}
	n := encodedReadNode{session: &encodedReadSession{payload: e.Bytes()}}
	r, err := readNode(n, Path{Endpoint: 1, Cluster: 0x28, Attribute: 19})
	if err == nil || !strings.Contains(err.Error(), "ACCESS DENIED") || r.Message != "" {
		t.Fatalf("status became fresh: %+v %v", r, err)
	}
}
