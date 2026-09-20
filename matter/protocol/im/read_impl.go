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

// ReadAttribute reads a single attribute over the Interaction Model,
// returning the decoded value as a tlv.Element so callers can extract
// whichever scalar type applies (UTF8()/Unsigned2()/Unsigned4()/...). It
// cannot represent a List/Array-typed attribute's value — a Decoder cannot
// buffer a whole list behind a single self-contained tlv.Element — use
// ReadListAttribute for those (see read_list_impl.go).
func ReadAttribute(sess SecureSession, endpointID EndpointID, clusterID ClusterID, attributeID AttributeID) (*ReadResponse, error) {
	responseRaw, err := doReadRequest(sess, endpointID, clusterID, attributeID)
	if err != nil {
		return nil, err
	}
	return parseReadResponse(responseRaw)
}

// ReadBoolAttribute reads a single boolean attribute over the Interaction Model.
func ReadBoolAttribute(sess SecureSession, endpointID EndpointID, clusterID ClusterID, attributeID AttributeID) (bool, error) {
	resp, err := ReadAttribute(sess, endpointID, clusterID, attributeID)
	if err != nil {
		return false, err
	}
	if resp.Status != nil {
		return false, fmt.Errorf("im: ReadResponse: attribute status IMStatus=%d ClusterStatus=%d", resp.Status.IMStatus, resp.Status.ClusterStatus)
	}
	if resp.Value == nil {
		return false, fmt.Errorf("im: ReadResponse missing attribute value")
	}
	v, ok := resp.Value.Bool()
	if !ok {
		return false, fmt.Errorf("im: ReadResponse attribute value is not a boolean")
	}
	return v, nil
}

// doReadRequest transmits a ReadRequest IM message for a single attribute
// path and returns the raw decrypted ReadResponse bytes (protocol header +
// TLV payload), for the caller to parse. Shared by ReadAttribute and
// ReadListAttribute.
func doReadRequest(sess SecureSession, endpointID EndpointID, clusterID ClusterID, attributeID AttributeID) ([]byte, error) {
	payload, err := buildReadRequestPayload(endpointID, clusterID, attributeID)
	if err != nil {
		return nil, fmt.Errorf("im: build ReadRequest payload: %w", err)
	}

	protocolHeaderBytes, exchangeID, err := buildIMProtocolHeader(message.ReadRequestMessage)
	if err != nil {
		return nil, fmt.Errorf("im: build protocol header: %w", err)
	}

	wire := make([]byte, 0, len(protocolHeaderBytes)+len(payload))
	wire = append(wire, protocolHeaderBytes...)
	wire = append(wire, payload...)

	log.HexDebug(wire)
	if err := sess.Transmit(wire); err != nil {
		return nil, fmt.Errorf("im: transmit ReadRequest: %w", err)
	}

	responseRaw, err := receiveExchangeResponse(sess, exchangeID)
	if err != nil {
		return nil, fmt.Errorf("im: receive ReadResponse: %w", err)
	}
	return responseRaw, nil
}

// buildReadRequestPayload encodes the ReadRequest TLV payload for a single
// attribute path.
//
// ReadRequestMessage TLV layout (spec section 10.7.2):
//
//	read-request-message => STRUCTURE {
//	  0: attribute-requests [LIST] {
//	    attribute-path-IB => LIST {
//	      2: endpoint  [UINT16]
//	      3: cluster   [UINT32]
//	      4: attribute [UINT32]
//	    }
//	  }
//	}
//
// The Node (tag 1) and ListIndex (tag 5) fields of AttributePathIB are
// wildcards when omitted and must NOT be encoded as an explicit 0: a present
// ListIndex on a path whose attribute is not list-typed is a malformed
// request per 10.6.2 and was rejected by a real device.
// 10.7.2. ReadRequestMessage / 10.6.2. AttributePathIB.
func buildReadRequestPayload(endpointID EndpointID, clusterID ClusterID, attributeID AttributeID) ([]byte, error) {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())

	enc.BeginArray(tlv.NewContextTag(0)) // attribute-requests

	enc.BeginList(tlv.NewAnonymousTag()) // attribute-path-IB
	enc.PutUnsigned2(tlv.NewContextTag(2), uint16(endpointID))
	if err := enc.PutUnsigned(tlv.NewContextTag(3), uint64(clusterID)); err != nil {
		return nil, err
	}
	if err := enc.PutUnsigned(tlv.NewContextTag(4), uint64(attributeID)); err != nil {
		return nil, err
	}
	if err := enc.EndContainer(); err != nil { // end attribute-path-IB
		return nil, err
	}

	if err := enc.EndContainer(); err != nil { // end attribute-requests
		return nil, err
	}

	// Tag 3: IsFabricFiltered. Although ReadRequestMessage::Parser::GetIsFabricFiltered
	// is documented as returning END_OF_TLV when absent, connectedhomeip's actual
	// server handler (ReadHandler::ProcessReadRequest) calls it unconditionally,
	// via ReturnErrorOnFailure, with no END_OF_TLV fallback — an omitted field
	// fails request processing entirely, and a real device replied with a
	// StatusResponseMessage(InvalidAction) for the whole ReadRequestMessage
	// instead of an attribute-specific error. It is therefore mandatory in
	// practice, not merely optional as its schema position suggests.
	// 10.7.2. ReadRequestMessage.
	enc.PutBool(tlv.NewContextTag(3), false)

	// Tag 0xFF: InteractionModelRevision. Mandatory trailing field on every
	// IM request/response message (spec 8.2.1, "Interaction Model Revision
	// Handling") — connectedhomeip's MessageBuilder::EncodeInteractionModelRevision
	// appends it unconditionally before closing the top-level structure. A
	// real device silently returned zero AttributeReportIBs for a
	// ReadRequestMessage missing this field instead of rejecting it outright.
	enc.PutUnsigned1(tlv.NewContextTag(interactionModelRevisionTag), interactionModelRevision)

	if err := enc.EndContainer(); err != nil { // end top-level structure
		return nil, err
	}
	return enc.Bytes(), nil
}

// parseReadResponse parses the decrypted payload of a ReadResponse
// (ReportDataMessage) message for the common case where the attribute's Data
// field (10.6.3) is a self-contained scalar — captured directly as a
// tlv.Element with no further decoding.
func parseReadResponse(data []byte) (*ReadResponse, error) {
	resp := &ReadResponse{}
	status, err := parseReadResponseCore(data, func(dec tlv.Decoder, elem tlv.Element) error {
		resp.Value = elem
		return nil
	})
	if err != nil {
		return nil, err
	}
	resp.Status = status
	return resp, nil
}

// parseReadResponseCore parses the decrypted payload of a ReadResponse
// (ReportDataMessage) message, walking its nested structure to extract the
// AttributeStatusIB or AttributeDataIB of the first AttributeReportIB (this
// client only ever reads one attribute path per ReadRequestMessage, see
// buildReadRequestPayload). dataFunc is invoked exactly once, at the
// AttributeDataIB's Data field (tag 2, 10.6.3), when the device returned
// attribute data rather than a status; it is not called at all when the
// device reported an AttributeStatusIB error for the path instead. A
// List/Array-typed Data field arrives as a nested container that dataFunc
// must fully consume itself (via dec.Next(), including its own
// EndOfContainer) before returning — see ReadListAttribute for that case.
// 10.7.9. ReportDataMessage.
func parseReadResponseCore(data []byte, dataFunc func(dec tlv.Decoder, elem tlv.Element) error) (*InvokeStatus, error) {
	protHdr, err := message.NewProtocolHeaderFromBytes(data)
	if err != nil {
		return nil, fmt.Errorf("im: parse protocol header: %w", err)
	}
	protoHdrBytes, err := protHdr.Bytes()
	if err != nil {
		return nil, fmt.Errorf("im: re-serialize protocol header: %w", err)
	}
	if len(data) <= len(protoHdrBytes) {
		return nil, fmt.Errorf("im: ReadResponse missing payload")
	}
	tlvData := data[len(protoHdrBytes):]

	// A device rejecting the whole ReadRequestMessage replies with a
	// StatusResponseMessage instead of a ReportDataMessage — same failure
	// mode as InvokeRequestMessage, see the matching comment in
	// parseInvokeResponse.
	if protHdr.Opcode().IsStatusResponseMessage() {
		status, err := parseStatusResponseMessage(tlvData)
		if err != nil {
			return nil, fmt.Errorf("im: ReadResponse: %w", err)
		}
		return &status, nil
	}

	dec := tlv.NewDecoderWithBytes(tlvData)
	if !dec.Next() {
		if err := dec.Error(); err != nil {
			return nil, fmt.Errorf("im: ReadResponse: %w", err)
		}
		return nil, fmt.Errorf("im: ReadResponse: empty payload")
	}
	if !dec.Element().Type().IsStructure() {
		return nil, fmt.Errorf("im: ReadResponse: expected top-level Structure")
	}

	var status *InvokeStatus
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
		case 1: // attribute-report-IBs
			if !elem.Type().IsList() && !elem.Type().IsArray() {
				return nil, fmt.Errorf("im: ReadResponse: attribute-report-IBs is not a list")
			}
			s, err := parseAttributeReportIBsCore(dec, dataFunc, &found)
			if err != nil {
				return nil, fmt.Errorf("im: ReadResponse: %w", err)
			}
			status = s
		default:
			if elem.Type().IsStructure() || elem.Type().IsList() || elem.Type().IsArray() {
				if err := skipContainer(dec); err != nil {
					return nil, fmt.Errorf("im: ReadResponse: %w", err)
				}
			}
		}
	}
	if err := dec.Error(); err != nil {
		return nil, fmt.Errorf("im: ReadResponse: %w", err)
	}
	if !found {
		return nil, fmt.Errorf("im: ReadResponse: no attribute report for requested path")
	}
	return status, nil
}

// parseAttributeReportIBsCore decodes the elements of the attribute-report-IBs
// list, assuming the caller has already consumed the List/Array-begin
// marker. Only the first AttributeReportIB is parsed; any further ones are
// skipped.
func parseAttributeReportIBsCore(dec tlv.Decoder, dataFunc func(dec tlv.Decoder, elem tlv.Element) error, found *bool) (*InvokeStatus, error) {
	var status *InvokeStatus
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			return status, dec.Error()
		}
		if !elem.Type().IsStructure() {
			return nil, fmt.Errorf("attribute-report-IB is not a structure")
		}
		if *found {
			if err := skipContainer(dec); err != nil {
				return nil, err
			}
			continue
		}
		s, err := parseAttributeReportIBCore(dec, dataFunc)
		if err != nil {
			return nil, err
		}
		status = s
		*found = true
	}
	return status, dec.Error()
}

// parseAttributeReportIBCore decodes an AttributeReportIB's fields, assuming
// the caller has already consumed the Structure-begin marker.
// 10.6.4. AttributeReportIB.
func parseAttributeReportIBCore(dec tlv.Decoder, dataFunc func(dec tlv.Decoder, elem tlv.Element) error) (*InvokeStatus, error) {
	var status *InvokeStatus
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
		case 0: // AttributeStatusIB
			if !elem.Type().IsStructure() {
				return nil, fmt.Errorf("AttributeStatusIB is not a structure")
			}
			s, err := parseAttributeStatusIBCore(dec)
			if err != nil {
				return nil, err
			}
			status = s
		case 1: // AttributeDataIB
			if !elem.Type().IsStructure() {
				return nil, fmt.Errorf("AttributeDataIB is not a structure")
			}
			if err := parseAttributeDataIBCore(dec, dataFunc); err != nil {
				return nil, err
			}
		default:
			if elem.Type().IsStructure() || elem.Type().IsList() || elem.Type().IsArray() {
				if err := skipContainer(dec); err != nil {
					return nil, err
				}
			}
		}
	}
	return status, dec.Error()
}

// parseAttributeStatusIBCore decodes an AttributeStatusIB's fields, assuming
// the caller has already consumed the Structure-begin marker.
// 10.6.5. AttributeStatusIB.
func parseAttributeStatusIBCore(dec tlv.Decoder) (*InvokeStatus, error) {
	var status *InvokeStatus
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
		case 1: // StatusIB
			if !elem.Type().IsStructure() {
				return nil, fmt.Errorf("StatusIB is not a structure")
			}
			s, err := decodeStatusIB(dec)
			if err != nil {
				return nil, err
			}
			status = &s
		default: // AttributePathIB (0)
			if elem.Type().IsStructure() || elem.Type().IsList() || elem.Type().IsArray() {
				if err := skipContainer(dec); err != nil {
					return nil, err
				}
			}
		}
	}
	return status, dec.Error()
}

// parseAttributeDataIBCore decodes an AttributeDataIB's fields, assuming the
// caller has already consumed the Structure-begin marker. dataFunc is called
// with the Data element (tag 2) — the attribute value itself, e.g. a Bool
// element directly for a boolean attribute, not a nested structure
// containing one.
// 10.6.3. AttributeDataIB.
func parseAttributeDataIBCore(dec tlv.Decoder, dataFunc func(dec tlv.Decoder, elem tlv.Element) error) error {
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
		case 2: // Data
			if err := dataFunc(dec, elem); err != nil {
				return err
			}
		default: // DataVersion (0), AttributePathIB (1)
			if elem.Type().IsStructure() || elem.Type().IsList() || elem.Type().IsArray() {
				if err := skipContainer(dec); err != nil {
					return err
				}
			}
		}
	}
	return dec.Error()
}
