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

// Package mockdevice implements an in-process fake Matter device — the
// responder side of PASE and CASE, plus a minimal Interaction Model server
// covering exactly the commands/attributes a commissioner needs during
// commissioning — so the real matter.Commissioner can be exercised
// end-to-end in tests without any live hardware.
package mockdevice

import (
	"fmt"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter/encoding/message"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	"github.com/cybergarage/go-matter/matter/protocol/im"
	"github.com/cybergarage/go-matter/matter/protocol/session"
)

// interactionModelRevisionTag/interactionModelRevision mirror
// matter/protocol/im's own unexported constants of the same name (the
// mandatory trailing field on every IM request/response message, spec
// 8.2.1) — duplicated here since im doesn't export them.
const (
	interactionModelRevisionTag uint8 = 0xFF
	interactionModelRevision    uint8 = 12
)

// invokeKey identifies a single (endpoint, cluster, command) triple.
type invokeKey struct {
	endpoint im.EndpointID
	cluster  im.ClusterID
	command  im.CommandID
}

// invokeHandler processes one InvokeRequest's command-fields (already
// decoded into a flat tag->element map — every command this server handles
// has non-nested fields, matching every command this repo's own clients
// send) and returns the CommandID and TLV-encoded CommandFields of the
// CommandDataIB to reply with. Returning a non-nil err sends a
// CommandStatusIB{InvalidCommand} instead.
type invokeHandler func(fields map[uint8]tlv.Element) (respCommandID im.CommandID, respFields []byte, err error)

// readKey identifies a single (endpoint, cluster, attribute) triple.
type readKey struct {
	endpoint  im.EndpointID
	cluster   im.ClusterID
	attribute im.AttributeID
}

// readHandler returns a closure that writes this attribute's Data element
// (10.6.3. AttributeDataIB, ContextTag(2)) into the ReportDataMessage being
// built — a scalar Put* call, or a BeginArray/.../EndContainer sequence for
// a list attribute. Returning a non-nil err sends an
// AttributeStatusIB{Failure} instead.
type readHandler func() (encodeData func(enc tlv.Encoder) error, err error)

// chunkedReadHandler returns the sequence of Data-field encoders to send as
// separate AttributeReportIBs for one attribute path (10.5.4.3, "List
// Chunking"): the first encoder writes the list's own (possibly empty)
// container, and each subsequent one writes a single item directly — not
// wrapped in another array — to append to it, matching how a real device
// split Descriptor's DeviceTypeList across two reports instead of sending
// it as a single non-chunked array. Registered instead of (never alongside)
// a plain readHandler for the same attribute.
type chunkedReadHandler func() (encodeChunks []func(enc tlv.Encoder) error, err error)

// imServer is a minimal Interaction Model server: it dispatches
// ReadRequestMessage/InvokeRequestMessage traffic received over a
// session.SecureSession to registered per-(endpoint,cluster,command/attribute)
// handlers, covering only what a commissioner needs during commissioning
// (spec 10.7.2 ReadRequestMessage / 10.7.9 InvokeRequestMessage and their
// responses) — not a general-purpose IM implementation.
type imServer struct {
	sess         session.SecureSession
	invokes      map[invokeKey]invokeHandler
	reads        map[readKey]readHandler
	chunkedReads map[readKey]chunkedReadHandler
}

func newIMServer(sess session.SecureSession) *imServer {
	return &imServer{
		sess:         sess,
		invokes:      make(map[invokeKey]invokeHandler),
		reads:        make(map[readKey]readHandler),
		chunkedReads: make(map[readKey]chunkedReadHandler),
	}
}

func (s *imServer) handleInvoke(endpoint im.EndpointID, cluster im.ClusterID, command im.CommandID, h invokeHandler) {
	s.invokes[invokeKey{endpoint, cluster, command}] = h
}

func (s *imServer) handleRead(endpoint im.EndpointID, cluster im.ClusterID, attribute im.AttributeID, h readHandler) {
	s.reads[readKey{endpoint, cluster, attribute}] = h
}

// handleChunkedRead registers h in place of (never alongside) handleRead
// for the same (endpoint, cluster, attribute) — see chunkedReadHandler.
func (s *imServer) handleChunkedRead(endpoint im.EndpointID, cluster im.ClusterID, attribute im.AttributeID, h chunkedReadHandler) {
	s.chunkedReads[readKey{endpoint, cluster, attribute}] = h
}

// serveOne receives and responds to exactly one IM request.
func (s *imServer) serveOne() error {
	raw, err := s.sess.Receive()
	if err != nil {
		return fmt.Errorf("mockdevice: im: receive: %w", err)
	}
	protHdr, err := message.NewProtocolHeaderFromBytes(raw)
	if err != nil {
		return fmt.Errorf("mockdevice: im: parse protocol header: %w", err)
	}
	protoHdrBytes, err := protHdr.Bytes()
	if err != nil {
		return fmt.Errorf("mockdevice: im: re-serialize protocol header: %w", err)
	}
	if len(raw) < len(protoHdrBytes) {
		return fmt.Errorf("mockdevice: im: request shorter than its own protocol header")
	}
	tlvData := raw[len(protoHdrBytes):]

	switch {
	case protHdr.Opcode().IsInvokeRequestMessage():
		return s.serveInvoke(protHdr.ExchangeID(), tlvData)
	case protHdr.Opcode().IsReadRequestMessage():
		return s.serveRead(protHdr.ExchangeID(), tlvData)
	default:
		return fmt.Errorf("mockdevice: im: unsupported request opcode 0x%02x", uint8(protHdr.Opcode()))
	}
}

// decodedInvokeRequest holds the single command-data-IB this server expects
// per InvokeRequestMessage (every commissioner command this repo sends
// invokes exactly one command per message, per im.Invoke's own doc comment).
type decodedInvokeRequest struct {
	endpoint im.EndpointID
	cluster  im.ClusterID
	command  im.CommandID
	fields   map[uint8]tlv.Element
}

func (s *imServer) serveInvoke(exchangeID message.ExchangeID, tlvData []byte) error {
	req, err := decodeInvokeRequest(tlvData)
	if err != nil {
		return fmt.Errorf("mockdevice: im: decode InvokeRequest: %w", err)
	}
	h, ok := s.invokes[invokeKey{req.endpoint, req.cluster, req.command}]
	if !ok {
		log.Debugf("mockdevice: im: no handler for endpoint=%d cluster=0x%X command=0x%X", req.endpoint, req.cluster, req.command)
		return s.sendInvokeStatus(exchangeID, req, 0x81 /* UnsupportedCommand */)
	}
	respCommand, respFields, err := h(req.fields)
	if err != nil {
		log.Debugf("mockdevice: im: handler for endpoint=%d cluster=0x%X command=0x%X failed: %v", req.endpoint, req.cluster, req.command, err)
		return s.sendInvokeStatus(exchangeID, req, 0x85 /* InvalidCommand */)
	}
	if respFields == nil {
		// A bare-success reply (e.g. AddTrustedRootCertificate, which per
		// spec 11.18.7.11 has no defined response payload): a
		// CommandStatusIB{SUCCESS}, not a CommandDataIB.
		return s.sendInvokeStatus(exchangeID, req, 0x00 /* Success */)
	}
	return s.sendInvokeData(exchangeID, req.endpoint, req.cluster, respCommand, respFields)
}

func (s *imServer) serveRead(exchangeID message.ExchangeID, tlvData []byte) error {
	req, err := decodeReadRequest(tlvData)
	if err != nil {
		return fmt.Errorf("mockdevice: im: decode ReadRequest: %w", err)
	}
	if ch, ok := s.chunkedReads[readKey(req)]; ok {
		encodeChunks, err := ch()
		if err != nil {
			return s.sendReadStatus(exchangeID, req, 0x01 /* Failure */)
		}
		return s.sendReadDataChunked(exchangeID, req.endpoint, req.cluster, req.attribute, encodeChunks)
	}
	h, ok := s.reads[readKey(req)]
	if !ok {
		return s.sendReadStatus(exchangeID, req, 0x86 /* UnsupportedAttribute */)
	}
	encodeData, err := h()
	if err != nil {
		return s.sendReadStatus(exchangeID, req, 0x01 /* Failure */)
	}
	return s.sendReadData(exchangeID, req.endpoint, req.cluster, req.attribute, encodeData)
}
