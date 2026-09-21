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

package mockdevice

import (
	"fmt"

	"github.com/cybergarage/go-matter/matter/encoding/message"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	"github.com/cybergarage/go-matter/matter/protocol/im"
)

// decodeInvokeRequest decodes an InvokeRequestMessage's TLV body (protocol
// header already stripped), mirroring matter/protocol/im's own
// buildInvokeRequestPayload layout in reverse (spec 10.7.9). Only the first
// command-data-IB is decoded — every command this repo's own clients send
// invokes exactly one command per message (see im.Invoke's doc comment).
func decodeInvokeRequest(tlvData []byte) (decodedInvokeRequest, error) {
	dec := tlv.NewDecoderWithBytes(tlvData)
	if !dec.Next() || !dec.Element().Type().IsStructure() {
		return decodedInvokeRequest{}, fmt.Errorf("expected top-level Structure")
	}
	var req decodedInvokeRequest
	found := false
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			break
		}
		ct, ok := elem.Tag().(tlv.ContextTag)
		if !ok {
			continue
		}
		if ct.ContextNumber() == 2 { // invoke-requests array
			if !elem.Type().IsArray() {
				return decodedInvokeRequest{}, fmt.Errorf("invoke-requests is not an array")
			}
			r, err := decodeFirstCommandDataIB(dec)
			if err != nil {
				return decodedInvokeRequest{}, err
			}
			req, found = r, true
			continue
		}
		if elem.Type().IsContainer() {
			if err := skipTLVContainer(dec); err != nil {
				return decodedInvokeRequest{}, err
			}
		}
	}
	if err := dec.Error(); err != nil {
		return decodedInvokeRequest{}, err
	}
	if !found {
		return decodedInvokeRequest{}, fmt.Errorf("missing invoke-requests")
	}
	return req, nil
}

func decodeFirstCommandDataIB(dec tlv.Decoder) (decodedInvokeRequest, error) {
	var req decodedInvokeRequest
	got := false
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			break
		}
		if got {
			if elem.Type().IsContainer() {
				if err := skipTLVContainer(dec); err != nil {
					return decodedInvokeRequest{}, err
				}
			}
			continue
		}
		if !elem.Type().IsStructure() {
			return decodedInvokeRequest{}, fmt.Errorf("command-data-IB is not a structure")
		}
		r, err := decodeCommandDataIBFields(dec)
		if err != nil {
			return decodedInvokeRequest{}, err
		}
		req, got = r, true
	}
	if !got {
		return decodedInvokeRequest{}, fmt.Errorf("empty invoke-requests array")
	}
	return req, dec.Error()
}

func decodeCommandDataIBFields(dec tlv.Decoder) (decodedInvokeRequest, error) {
	var req decodedInvokeRequest
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			break
		}
		ct, ok := elem.Tag().(tlv.ContextTag)
		if !ok {
			continue
		}
		switch ct.ContextNumber() {
		case 0: // command-path-IB
			if !elem.Type().IsList() {
				return decodedInvokeRequest{}, fmt.Errorf("command-path-IB is not a list")
			}
			ep, cl, cmd, err := decodeCommandPathIB(dec)
			if err != nil {
				return decodedInvokeRequest{}, err
			}
			req.endpoint, req.cluster, req.command = ep, cl, cmd
		case 1: // command-fields
			if !elem.Type().IsStructure() {
				return decodedInvokeRequest{}, fmt.Errorf("command-fields is not a structure")
			}
			fields, err := decodeFlatFields(dec)
			if err != nil {
				return decodedInvokeRequest{}, err
			}
			req.fields = fields
		default:
			if elem.Type().IsContainer() {
				if err := skipTLVContainer(dec); err != nil {
					return decodedInvokeRequest{}, err
				}
			}
		}
	}
	return req, dec.Error()
}

func decodeCommandPathIB(dec tlv.Decoder) (im.EndpointID, im.ClusterID, im.CommandID, error) {
	var ep im.EndpointID
	var cl im.ClusterID
	var cmd im.CommandID
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			break
		}
		ct, ok := elem.Tag().(tlv.ContextTag)
		if !ok {
			continue
		}
		switch ct.ContextNumber() {
		case 0:
			v, _ := elem.Unsigned()
			ep = im.EndpointID(v)
		case 1:
			v, _ := elem.Unsigned()
			cl = im.ClusterID(v)
		case 2:
			v, _ := elem.Unsigned()
			cmd = im.CommandID(v)
		}
	}
	return ep, cl, cmd, dec.Error()
}

func decodeFlatFields(dec tlv.Decoder) (map[uint8]tlv.Element, error) {
	out := make(map[uint8]tlv.Element)
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			return out, dec.Error()
		}
		ct, ok := elem.Tag().(tlv.ContextTag)
		if !ok {
			continue
		}
		out[uint8(ct.ContextNumber())] = elem
	}
	return nil, dec.Error()
}

func skipTLVContainer(dec tlv.Decoder) error {
	depth := 1
	for dec.Next() {
		switch {
		case dec.Element().Type().IsEndOfContainer():
			depth--
			if depth == 0 {
				return dec.Error()
			}
		case dec.Element().Type().IsContainer():
			depth++
		}
	}
	return dec.Error()
}

// decodedReadRequest holds the single attribute-path-IB this server expects
// per ReadRequestMessage (this repo's own client only ever reads one
// attribute path per message — matter/protocol/im's ReadBoolAttribute).
type decodedReadRequest struct {
	endpoint  im.EndpointID
	cluster   im.ClusterID
	attribute im.AttributeID
}

func decodeReadRequest(tlvData []byte) (decodedReadRequest, error) {
	dec := tlv.NewDecoderWithBytes(tlvData)
	if !dec.Next() || !dec.Element().Type().IsStructure() {
		return decodedReadRequest{}, fmt.Errorf("expected top-level Structure")
	}
	var req decodedReadRequest
	found := false
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			break
		}
		ct, ok := elem.Tag().(tlv.ContextTag)
		if !ok {
			continue
		}
		if ct.ContextNumber() == 0 { // attribute-requests array
			if !elem.Type().IsArray() {
				return decodedReadRequest{}, fmt.Errorf("attribute-requests is not an array")
			}
			r, err := decodeFirstAttributePathIB(dec)
			if err != nil {
				return decodedReadRequest{}, err
			}
			req, found = r, true
			continue
		}
		if elem.Type().IsContainer() {
			if err := skipTLVContainer(dec); err != nil {
				return decodedReadRequest{}, err
			}
		}
	}
	if err := dec.Error(); err != nil {
		return decodedReadRequest{}, err
	}
	if !found {
		return decodedReadRequest{}, fmt.Errorf("missing attribute-requests")
	}
	return req, nil
}

func decodeFirstAttributePathIB(dec tlv.Decoder) (decodedReadRequest, error) {
	var req decodedReadRequest
	got := false
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			break
		}
		if got {
			if elem.Type().IsContainer() {
				if err := skipTLVContainer(dec); err != nil {
					return decodedReadRequest{}, err
				}
			}
			continue
		}
		if !elem.Type().IsList() {
			return decodedReadRequest{}, fmt.Errorf("attribute-path-IB is not a list")
		}
		for dec.Next() {
			fe := dec.Element()
			if fe.Type().IsEndOfContainer() {
				break
			}
			ct, ok := fe.Tag().(tlv.ContextTag)
			if !ok {
				continue
			}
			switch ct.ContextNumber() {
			case 2:
				v, _ := fe.Unsigned()
				req.endpoint = im.EndpointID(v)
			case 3:
				v, _ := fe.Unsigned()
				req.cluster = im.ClusterID(v)
			case 4:
				v, _ := fe.Unsigned()
				req.attribute = im.AttributeID(v)
			}
		}
		got = true
	}
	if !got {
		return decodedReadRequest{}, fmt.Errorf("empty attribute-requests array")
	}
	return req, dec.Error()
}

// sendIMMessage wraps payload in the IM protocol header and transmits it —
// the server-side mirror of im.Invoke/im.ReadBoolAttribute's own request
// framing.
func (s *imServer) sendIMMessage(exchangeID message.ExchangeID, opcode message.Opcode, payload []byte) error {
	hdr := message.NewProtocolHeader(
		message.WithHeaderExchangeFlags(message.ReliabilityFlag),
		message.WithHeaderOpcode(opcode),
		message.WithHeaderExchangeID(exchangeID),
		message.WithHeaderProtocolID(message.InteractionModel),
	)
	hdrBytes, err := hdr.Bytes()
	if err != nil {
		return err
	}
	wire := make([]byte, 0, len(hdrBytes)+len(payload))
	wire = append(wire, hdrBytes...)
	wire = append(wire, payload...)
	return s.sess.Transmit(wire)
}

// sendInvokeData replies to an InvokeRequest with a CommandDataIB — a
// successful invocation that returns data. fields must be a single,
// self-delimiting TLV element already tagged ContextTag(1) (the
// CommandFields slot), matching how im.Invoke's own commandFields parameter
// is documented and spliced in via enc.Raw.
// 10.7.17.1. InvokeResponseIB / 10.7.17.3. CommandDataIB.
func (s *imServer) sendInvokeData(exchangeID message.ExchangeID, endpoint im.EndpointID, cluster im.ClusterID, command im.CommandID, fields []byte) error {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	enc.PutBool(tlv.NewContextTag(0), false)  // suppressResponse
	enc.BeginArray(tlv.NewContextTag(1))      // invoke-responses
	enc.BeginStructure(tlv.NewAnonymousTag()) // InvokeResponseIB
	enc.BeginStructure(tlv.NewContextTag(0))  // CommandDataIB
	enc.BeginList(tlv.NewContextTag(0))       // command-path-IB
	enc.PutUnsigned2(tlv.NewContextTag(0), uint16(endpoint))
	if err := enc.PutUnsigned(tlv.NewContextTag(1), uint64(cluster)); err != nil {
		return err
	}
	if err := enc.PutUnsigned(tlv.NewContextTag(2), uint64(command)); err != nil {
		return err
	}
	if err := enc.EndContainer(); err != nil { // end command-path-IB
		return err
	}
	if len(fields) > 0 {
		enc.Raw(fields)
	}
	if err := enc.EndContainer(); err != nil { // end CommandDataIB
		return err
	}
	if err := enc.EndContainer(); err != nil { // end InvokeResponseIB
		return err
	}
	if err := enc.EndContainer(); err != nil { // end invoke-responses
		return err
	}
	enc.PutUnsigned1(tlv.NewContextTag(interactionModelRevisionTag), interactionModelRevision)
	if err := enc.EndContainer(); err != nil { // end top-level
		return err
	}
	return s.sendIMMessage(exchangeID, message.InvokeResponseMessage, enc.Bytes())
}

// sendInvokeStatus replies to an InvokeRequest with a CommandStatusIB —
// the command was recognized but rejected. imStatus is an Interaction
// Model status code (spec 8.10, Table "Status Code Table"), not a
// cluster-specific one.
// 10.7.17.1. InvokeResponseIB / 10.7.17.2. StatusIB.
func (s *imServer) sendInvokeStatus(exchangeID message.ExchangeID, req decodedInvokeRequest, imStatus uint8) error {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	enc.PutBool(tlv.NewContextTag(0), false)
	enc.BeginArray(tlv.NewContextTag(1))
	enc.BeginStructure(tlv.NewAnonymousTag()) // InvokeResponseIB
	enc.BeginStructure(tlv.NewContextTag(1))  // CommandStatusIB
	enc.BeginList(tlv.NewContextTag(0))       // command-path-IB
	enc.PutUnsigned2(tlv.NewContextTag(0), uint16(req.endpoint))
	if err := enc.PutUnsigned(tlv.NewContextTag(1), uint64(req.cluster)); err != nil {
		return err
	}
	if err := enc.PutUnsigned(tlv.NewContextTag(2), uint64(req.command)); err != nil {
		return err
	}
	if err := enc.EndContainer(); err != nil { // end command-path-IB
		return err
	}
	enc.BeginStructure(tlv.NewContextTag(1)) // StatusIB
	enc.PutUnsigned1(tlv.NewContextTag(0), imStatus)
	if err := enc.EndContainer(); err != nil { // end StatusIB
		return err
	}
	if err := enc.EndContainer(); err != nil { // end CommandStatusIB
		return err
	}
	if err := enc.EndContainer(); err != nil { // end InvokeResponseIB
		return err
	}
	if err := enc.EndContainer(); err != nil { // end invoke-responses
		return err
	}
	enc.PutUnsigned1(tlv.NewContextTag(interactionModelRevisionTag), interactionModelRevision)
	if err := enc.EndContainer(); err != nil {
		return err
	}
	return s.sendIMMessage(exchangeID, message.InvokeResponseMessage, enc.Bytes())
}

// sendReadData replies to a ReadRequest with an AttributeDataIB carrying an
// arbitrary attribute value, written by encodeData at the Data element
// (ContextTag(2)) — a scalar Put* call, or a BeginArray/.../EndContainer
// sequence for a list attribute.
// 10.7.9. ReportDataMessage / 10.6.3. AttributeDataIB.
func (s *imServer) sendReadData(exchangeID message.ExchangeID, endpoint im.EndpointID, cluster im.ClusterID, attribute im.AttributeID, encodeData func(enc tlv.Encoder) error) error {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	enc.BeginArray(tlv.NewContextTag(1))      // attribute-report-IBs
	enc.BeginStructure(tlv.NewAnonymousTag()) // AttributeReportIB
	enc.BeginStructure(tlv.NewContextTag(1))  // AttributeDataIB
	enc.PutUnsigned4(tlv.NewContextTag(0), 0) // DataVersion
	enc.BeginList(tlv.NewContextTag(1))       // AttributePathIB
	enc.PutUnsigned2(tlv.NewContextTag(2), uint16(endpoint))
	if err := enc.PutUnsigned(tlv.NewContextTag(3), uint64(cluster)); err != nil {
		return err
	}
	if err := enc.PutUnsigned(tlv.NewContextTag(4), uint64(attribute)); err != nil {
		return err
	}
	if err := enc.EndContainer(); err != nil { // end AttributePathIB
		return err
	}
	if err := encodeData(enc); err != nil { // Data
		return err
	}
	if err := enc.EndContainer(); err != nil { // end AttributeDataIB
		return err
	}
	if err := enc.EndContainer(); err != nil { // end AttributeReportIB
		return err
	}
	if err := enc.EndContainer(); err != nil { // end attribute-report-IBs
		return err
	}
	enc.PutUnsigned1(tlv.NewContextTag(interactionModelRevisionTag), interactionModelRevision)
	if err := enc.EndContainer(); err != nil {
		return err
	}
	return s.sendIMMessage(exchangeID, message.ReportDataMessage, enc.Bytes())
}

// sendReadStatus replies to a ReadRequest with an AttributeStatusIB — the
// attribute path was recognized but could not be read.
// 10.6.5. AttributeStatusIB.
func (s *imServer) sendReadStatus(exchangeID message.ExchangeID, req decodedReadRequest, imStatus uint8) error {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	enc.BeginArray(tlv.NewContextTag(1))
	enc.BeginStructure(tlv.NewAnonymousTag()) // AttributeReportIB
	enc.BeginStructure(tlv.NewContextTag(0))  // AttributeStatusIB
	enc.BeginList(tlv.NewContextTag(0))       // AttributePathIB
	enc.PutUnsigned2(tlv.NewContextTag(2), uint16(req.endpoint))
	if err := enc.PutUnsigned(tlv.NewContextTag(3), uint64(req.cluster)); err != nil {
		return err
	}
	if err := enc.PutUnsigned(tlv.NewContextTag(4), uint64(req.attribute)); err != nil {
		return err
	}
	if err := enc.EndContainer(); err != nil { // end AttributePathIB
		return err
	}
	enc.BeginStructure(tlv.NewContextTag(1)) // StatusIB
	enc.PutUnsigned1(tlv.NewContextTag(0), imStatus)
	if err := enc.EndContainer(); err != nil { // end StatusIB
		return err
	}
	if err := enc.EndContainer(); err != nil { // end AttributeStatusIB
		return err
	}
	if err := enc.EndContainer(); err != nil { // end AttributeReportIB
		return err
	}
	if err := enc.EndContainer(); err != nil { // end attribute-report-IBs
		return err
	}
	enc.PutUnsigned1(tlv.NewContextTag(interactionModelRevisionTag), interactionModelRevision)
	if err := enc.EndContainer(); err != nil {
		return err
	}
	return s.sendIMMessage(exchangeID, message.ReportDataMessage, enc.Bytes())
}
