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

package im

import (
	"fmt"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter/encoding/message"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
)

// interactionModelRevisionTag and interactionModelRevision encode the
// mandatory trailing field present on every IM request/response message
// (spec 8.2.1, "Interaction Model Revision Handling"). connectedhomeip's
// MessageBuilder::EncodeInteractionModelRevision appends
// ContextTag(0xFF) = kInteractionModelRevision (currently 12) unconditionally
// before closing each message's top-level structure.
const (
	interactionModelRevisionTag uint8 = 0xFF
	interactionModelRevision    uint8 = 12
)

// Invoke sends an InvokeRequest IM message over the given secure session and waits
// for an InvokeResponse. commandFields may be nil for commands with no fields.
//
// InvokeRequest TLV layout (spec section 10.7.9):
//
//	invoke-request-message => STRUCTURE {
//	  0: suppress-response  [BOOL]
//	  1: timed-request      [BOOL]
//	  2: invoke-requests    [ARRAY] {
//	    command-data-IB => STRUCTURE {
//	      0: command-path-IB => LIST {
//	        0: endpoint-id  [UINT16]
//	        1: cluster-id   [UINT32]
//	        2: command-id   [UINT32]
//	      }
//	      1: command-fields [STRUCTURE] (optional)
//	    }
//	  }
//	}
//
// 10.7.9. InvokeRequestMessage.
func Invoke(sess SecureSession, endpointID EndpointID, clusterID ClusterID, commandID CommandID, commandFields []byte) (*InvokeResponse, error) {
	// Build InvokeRequest TLV payload.
	payload, err := buildInvokeRequestPayload(endpointID, clusterID, commandID, commandFields)
	if err != nil {
		return nil, fmt.Errorf("im: build InvokeRequest payload: %w", err)
	}

	// Wrap payload in the IM protocol header and send over the secure session.
	protocolHeaderBytes, exchangeID, err := buildIMProtocolHeader(message.InvokeRequestMessage)
	if err != nil {
		return nil, fmt.Errorf("im: build protocol header: %w", err)
	}

	// Transmit: protocol header bytes || TLV payload.
	wire := make([]byte, 0, len(protocolHeaderBytes)+len(payload))
	wire = append(wire, protocolHeaderBytes...)
	wire = append(wire, payload...)

	if err := sess.Transmit(wire); err != nil {
		return nil, fmt.Errorf("im: transmit InvokeRequest: %w", err)
	}

	// Receive the InvokeResponse.
	responseRaw, err := receiveExchangeResponse(sess, exchangeID)
	if err != nil {
		return nil, fmt.Errorf("im: receive InvokeResponse: %w", err)
	}

	return parseInvokeResponse(responseRaw)
}

// buildInvokeRequestPayload encodes the InvokeRequest TLV payload.
func buildInvokeRequestPayload(endpointID EndpointID, clusterID ClusterID, commandID CommandID, commandFields []byte) ([]byte, error) {
	enc := tlv.NewEncoder()

	// Anonymous top-level structure.
	enc.BeginStructure(tlv.NewAnonymousTag())

	// Tag 0: suppress-response = false.
	enc.PutBool(tlv.NewContextTag(0), false)
	// Tag 1: timed-request = false.
	enc.PutBool(tlv.NewContextTag(1), false)

	// Tag 2: invoke-requests. InvokeRequests (src/app/MessageDef/InvokeRequests.h)
	// is an ArrayParser/ArrayBuilder, i.e. TLV type Array, not List — a real
	// device's ProcessInvokeRequest calls GetInvokeRequests unconditionally
	// and returns Status::InvalidAction for the whole message on any error,
	// including a container-type mismatch.
	enc.BeginArray(tlv.NewContextTag(2))

	// command-data-IB structure.
	enc.BeginStructure(tlv.NewAnonymousTag())

	// Tag 0: command-path-IB. CommandPathIB (src/app/MessageDef/CommandPathIB.h)
	// is a ListParser/ListBuilder, i.e. TLV type List, not Structure — same
	// failure mode as InvokeRequests above.
	enc.BeginList(tlv.NewContextTag(0))
	enc.PutUnsigned2(tlv.NewContextTag(0), uint16(endpointID))
	if err := enc.PutUnsigned(tlv.NewContextTag(1), uint64(clusterID)); err != nil {
		return nil, err
	}
	if err := enc.PutUnsigned(tlv.NewContextTag(2), uint64(commandID)); err != nil {
		return nil, err
	}
	if err := enc.EndContainer(); err != nil { // end command-path-IB
		return nil, err
	}

	// Tag 1: command-fields (optional structure, per 10.7.9). commandFields
	// holds a fully self-delimiting TLV element (built by the caller's
	// field-builder, tagged with ContextTag(1) so it lands correctly here)
	// spliced in verbatim — it must NOT be wrapped as an octet string, since
	// the spec requires command-fields to literally be a STRUCTURE.
	if len(commandFields) > 0 {
		enc.Raw(commandFields)
	}

	if err := enc.EndContainer(); err != nil { // end command-data-IB
		return nil, err
	}
	if err := enc.EndContainer(); err != nil { // end invoke-requests list
		return nil, err
	}

	enc.PutUnsigned1(tlv.NewContextTag(interactionModelRevisionTag), interactionModelRevision)

	if err := enc.EndContainer(); err != nil { // end top-level structure
		return nil, err
	}

	return enc.Bytes(), nil
}

// buildIMProtocolHeader builds the Matter protocol header bytes for an IM
// message, returning the ExchangeID it generated so the caller can match it
// against the ExchangeID of whatever message it eventually receives back —
// see receiveExchangeResponse.
func buildIMProtocolHeader(opcode message.Opcode) ([]byte, message.ExchangeID, error) {
	exchangeID := message.NewFirstExchangeID()
	hdr := message.NewProtocolHeader(
		message.WithHeaderExchangeFlags(message.InitiatorFlag|message.ReliabilityFlag),
		message.WithHeaderOpcode(opcode),
		message.WithHeaderExchangeID(exchangeID),
		message.WithHeaderProtocolID(message.InteractionModel),
	)
	b, err := hdr.Bytes()
	return b, exchangeID, err
}

// receiveExchangeResponse reads messages from sess until one arrives whose
// ExchangeID matches exchangeID, discarding any others. Each im.Invoke /
// im.ReadBoolAttribute call opens a brand-new exchange per request, and
// nothing below the IM layer knows which exchange the caller is currently
// waiting for — SecureSession.Receive only filters what it can generically
// recognize as not belonging to this session at all (a different SessionID)
// or as needing no application-level response (a standalone MRP ack). A
// message that legitimately belongs to this session but to a different,
// unrelated exchange — observed against a real device as a late duplicate
// retransmission of an earlier response, arriving after this client had
// already moved on to a later request — passes both of those checks and
// must be filtered here instead, by the one thing that actually identifies
// which request a response answers.
// 4.10.2. Exchange ID.
func receiveExchangeResponse(sess SecureSession, exchangeID message.ExchangeID) ([]byte, error) {
	for {
		raw, err := sess.Receive()
		if err != nil {
			return nil, err
		}
		protHdr, err := message.NewProtocolHeaderFromBytes(raw)
		if err != nil {
			return nil, fmt.Errorf("im: parse protocol header: %w", err)
		}
		if protHdr.ExchangeID() != exchangeID {
			log.Debugf("im: received message for a different exchange (got %v, want %v), waiting for next message", protHdr.ExchangeID(), exchangeID)
			continue
		}
		return raw, nil
	}
}

// parseInvokeResponse parses the decrypted payload of an InvokeResponse message,
// walking its nested structure to extract the status and/or response fields of
// the first InvokeResponseIB (this client only ever sends one command per
// InvokeRequestMessage, see buildInvokeRequestPayload).
// 10.7.17. InvokeResponseMessage / 10.7.17.1. InvokeResponseIB.
func parseInvokeResponse(data []byte) (*InvokeResponse, error) {
	// Skip protocol header bytes to get to the TLV payload.
	if len(data) < 6 {
		return nil, fmt.Errorf("im: InvokeResponse too short (%d bytes)", len(data))
	}
	// Parse the protocol header to find where TLV starts.
	protHdr, err := message.NewProtocolHeaderFromBytes(data)
	if err != nil {
		return nil, fmt.Errorf("im: parse protocol header: %w", err)
	}
	protoHdrBytes, err := protHdr.Bytes()
	if err != nil {
		return nil, fmt.Errorf("im: re-serialize protocol header: %w", err)
	}
	if len(data) <= len(protoHdrBytes) {
		// No TLV payload — treat as success with empty payload.
		return &InvokeResponse{}, nil
	}
	tlvData := data[len(protoHdrBytes):]

	// A device rejecting the whole InvokeRequestMessage (e.g. a malformed
	// or unsupported request) replies with a StatusResponseMessage instead
	// of an InvokeResponseMessage. Its TLV body shares no tag layout with
	// InvokeResponseMessage's (Status sits directly at tag 0, not nested
	// under an InvokeResponseIB/CommandStatusIB/StatusIB chain), so it must
	// be detected via the protocol opcode and parsed separately — otherwise
	// every field silently fails to match any case below and IsSuccess()
	// incorrectly reports success for the default zero-value Status.
	if protHdr.Opcode().IsStatusResponseMessage() {
		status, err := parseStatusResponseMessage(tlvData)
		if err != nil {
			return nil, fmt.Errorf("im: InvokeResponse: %w", err)
		}
		return &InvokeResponse{Status: status}, nil
	}

	dec := tlv.NewDecoderWithBytes(tlvData)
	if !dec.Next() {
		if err := dec.Error(); err != nil {
			return nil, fmt.Errorf("im: InvokeResponse: %w", err)
		}
		return nil, fmt.Errorf("im: InvokeResponse: empty payload")
	}
	if !dec.Element().Type().IsStructure() {
		return nil, fmt.Errorf("im: InvokeResponse: expected top-level Structure")
	}

	resp := &InvokeResponse{}
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
		switch ct.ContextNumber() {
		case 1: // invoke-responses list
			if !elem.Type().IsList() && !elem.Type().IsArray() {
				return nil, fmt.Errorf("im: InvokeResponse: invoke-responses is not a list")
			}
			if err := parseInvokeResponses(dec, resp, &found); err != nil {
				return nil, fmt.Errorf("im: InvokeResponse: %w", err)
			}
		default:
			if elem.Type().IsStructure() || elem.Type().IsList() || elem.Type().IsArray() {
				if err := skipContainer(dec); err != nil {
					return nil, fmt.Errorf("im: InvokeResponse: %w", err)
				}
			}
		}
	}
	if err := dec.Error(); err != nil {
		return nil, fmt.Errorf("im: InvokeResponse: %w", err)
	}
	return resp, nil
}

// parseInvokeResponses decodes the elements of the invoke-responses list,
// assuming the caller has already consumed the List-begin marker. Only the
// first InvokeResponseIB is parsed into resp; any further ones are skipped.
func parseInvokeResponses(dec tlv.Decoder, resp *InvokeResponse, found *bool) error {
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			return dec.Error()
		}
		if !elem.Type().IsStructure() {
			return fmt.Errorf("invoke-response-IB is not a structure")
		}
		if *found {
			if err := skipContainer(dec); err != nil {
				return err
			}
			continue
		}
		if err := parseInvokeResponseIB(dec, resp); err != nil {
			return err
		}
		*found = true
	}
	return dec.Error()
}

// parseInvokeResponseIB decodes an InvokeResponseIB's fields, assuming the
// caller has already consumed the Structure-begin marker.
// 10.7.17.1. InvokeResponseIB.
func parseInvokeResponseIB(dec tlv.Decoder, resp *InvokeResponse) error {
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			return dec.Error()
		}
		ct, ok := elem.Tag().(tlv.ContextTag)
		if !ok {
			continue
		}
		switch ct.ContextNumber() {
		case 0: // CommandDataIB
			if !elem.Type().IsStructure() {
				return fmt.Errorf("CommandDataIB is not a structure")
			}
			if err := parseCommandDataIB(dec, resp); err != nil {
				return err
			}
		case 1: // CommandStatusIB
			if !elem.Type().IsStructure() {
				return fmt.Errorf("CommandStatusIB is not a structure")
			}
			if err := parseCommandStatusIB(dec, resp); err != nil {
				return err
			}
		default:
			if elem.Type().IsStructure() || elem.Type().IsList() || elem.Type().IsArray() {
				if err := skipContainer(dec); err != nil {
					return err
				}
			}
		}
	}
	return dec.Error()
}

// parseCommandStatusIB decodes a CommandStatusIB's fields, assuming the
// caller has already consumed the Structure-begin marker.
func parseCommandStatusIB(dec tlv.Decoder, resp *InvokeResponse) error {
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			return dec.Error()
		}
		ct, ok := elem.Tag().(tlv.ContextTag)
		if !ok {
			continue
		}
		switch ct.ContextNumber() {
		case 1: // StatusIB
			if !elem.Type().IsStructure() {
				return fmt.Errorf("StatusIB is not a structure")
			}
			if err := parseStatusIB(dec, resp); err != nil {
				return err
			}
		default: // CommandPathIB (0) and any future fields.
			if elem.Type().IsStructure() || elem.Type().IsList() || elem.Type().IsArray() {
				if err := skipContainer(dec); err != nil {
					return err
				}
			}
		}
	}
	return dec.Error()
}

// parseStatusIB decodes a StatusIB's fields, assuming the caller has already
// consumed the Structure-begin marker.
// 10.7.17.2. Status IB.
func parseStatusIB(dec tlv.Decoder, resp *InvokeResponse) error {
	status, err := decodeStatusIB(dec)
	if err != nil {
		return err
	}
	resp.Status = status
	return nil
}

// parseStatusResponseMessage decodes a StatusResponseMessage's TLV body
// (protocol header already stripped). Unlike StatusIB, which is always
// nested one or more levels deep (InvokeResponseIB.CommandStatusIB.StatusIB,
// or AttributeStatusIB.StatusIB), a StatusResponseMessage carries its Status
// code directly as tag 0 of the top-level structure, with no ClusterStatus.
// 10.7.16. StatusResponseMessage.
func parseStatusResponseMessage(tlvData []byte) (InvokeStatus, error) {
	var status InvokeStatus
	dec := tlv.NewDecoderWithBytes(tlvData)
	if !dec.Next() || !dec.Element().Type().IsStructure() {
		return status, fmt.Errorf("expected top-level Structure")
	}
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			break
		}
		ct, ok := elem.Tag().(tlv.ContextTag)
		if !ok {
			continue
		}
		if ct.ContextNumber() == 0 {
			if v, ok := elem.Unsigned1(); ok {
				status.IMStatus = v
			}
		}
	}
	return status, dec.Error()
}

// decodeStatusIB decodes a StatusIB's fields, assuming the caller has
// already consumed the Structure-begin marker. Shared by InvokeResponseIB
// (10.7.17.2) and AttributeStatusIB (10.6.5) parsing, which both nest a
// StatusIB identically.
func decodeStatusIB(dec tlv.Decoder) (InvokeStatus, error) {
	var status InvokeStatus
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			return status, dec.Error()
		}
		ct, ok := elem.Tag().(tlv.ContextTag)
		if !ok {
			continue
		}
		switch ct.ContextNumber() {
		case 0:
			if v, ok := elem.Unsigned1(); ok {
				status.IMStatus = v
			}
		case 1:
			if v, ok := elem.Unsigned1(); ok {
				status.ClusterStatus = v
			}
		}
	}
	return status, dec.Error()
}

// parseCommandDataIB decodes a CommandDataIB's fields, assuming the caller
// has already consumed the Structure-begin marker.
func parseCommandDataIB(dec tlv.Decoder, resp *InvokeResponse) error {
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			return dec.Error()
		}
		ct, ok := elem.Tag().(tlv.ContextTag)
		if !ok {
			continue
		}
		switch ct.ContextNumber() {
		case 1: // CommandFields
			if !elem.Type().IsStructure() {
				return fmt.Errorf("CommandFields is not a structure")
			}
			payload, err := parseFlatFields(dec)
			if err != nil {
				return err
			}
			resp.Payload = payload
		default: // CommandPathIB (0) and any future fields.
			if elem.Type().IsStructure() || elem.Type().IsList() || elem.Type().IsArray() {
				if err := skipContainer(dec); err != nil {
					return err
				}
			}
		}
	}
	return dec.Error()
}

// parseFlatFields decodes a flat (non-nested) structure's context-tagged
// elements into a map, assuming the caller has already consumed the
// Structure-begin marker. This is sufficient for every command response this
// client decodes (AttestationResponse, CertificateChainResponse, CSRResponse,
// NOCResponse, NetworkConfigResponse, ConnectNetworkResponse), none of which
// nest containers inside their command fields.
func parseFlatFields(dec tlv.Decoder) (map[uint8]tlv.Element, error) {
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

// skipContainer consumes and discards a container's contents, assuming the
// caller has already consumed its Structure/List/Array-begin marker. It
// correctly handles arbitrarily nested containers within.
func skipContainer(dec tlv.Decoder) error {
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
