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

func TestEncodedStructureCannotBecomeFreshScalarObservation(t *testing.T) {
	e := tlv.NewEncoder()
	e.BeginStructure(tlv.NewAnonymousTag())
	e.BeginArray(tlv.NewContextTag(1))
	e.BeginStructure(tlv.NewAnonymousTag())
	e.BeginStructure(tlv.NewContextTag(1)) // AttributeDataIB
	e.BeginList(tlv.NewContextTag(1))      // Exact fixture path.
	e.PutUnsigned2(tlv.NewContextTag(2), 1)
	e.PutUnsigned4(tlv.NewContextTag(3), 0xDEAD)
	e.PutUnsigned4(tlv.NewContextTag(4), 0x1234)
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
	node := encodedReadNode{session: &encodedReadSession{payload: e.Bytes()}}
	result, err := readNode(node, Path{Endpoint: 1, Cluster: 0xDEAD, Attribute: 0x1234})
	if err == nil || !strings.Contains(err.Error(), "UNSUPPORTED") || !strings.Contains(err.Error(), "value unknown") || result.Message != "" {
		t.Fatalf("container misrepresented: result=%+v error=%v", result, err)
	}
}
