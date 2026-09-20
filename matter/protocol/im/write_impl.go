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

// WriteAttribute sends a WriteRequest IM message for a single attribute path
// and waits for a WriteResponse. encodeData is called once, with the
// top-level encoder, to append the AttributeDataIB's Data field (10.6.3, tag
// 2) — e.g. `enc.PutBool(tlv.NewContextTag(2), true)` for a boolean
// attribute — mirroring how buildReadRequestPayload/buildInvokeRequestPayload
// compose an Encoder directly rather than via a typed helper per attribute.
//
// WriteRequestMessage TLV layout (spec section 10.7.4):
//
//	write-request-message => STRUCTURE {
//	  0: suppress-response      [BOOL]
//	  1: timed-request          [BOOL]
//	  2: write-requests         [ARRAY] {
//	    attribute-data-IB => STRUCTURE {
//	      1: attribute-path-IB => LIST {
//	        2: endpoint  [UINT16]
//	        3: cluster   [UINT32]
//	        4: attribute [UINT32]
//	      }
//	      2: data [ANY] (from encodeData)
//	    }
//	  }
//	  3: more-chunked-messages  [BOOL]
//	}
//
// 10.7.4. WriteRequestMessage / 10.6.3. AttributeDataIB.
func WriteAttribute(sess SecureSession, endpointID EndpointID, clusterID ClusterID, attributeID AttributeID, encodeData func(enc tlv.Encoder) error) (*WriteResponse, error) {
	payload, err := buildWriteRequestPayload(endpointID, clusterID, attributeID, encodeData)
	if err != nil {
		return nil, fmt.Errorf("im: build WriteRequest payload: %w", err)
	}

	protocolHeaderBytes, exchangeID, err := buildIMProtocolHeader(message.WriteRequestMessage)
	if err != nil {
		return nil, fmt.Errorf("im: build protocol header: %w", err)
	}

	wire := make([]byte, 0, len(protocolHeaderBytes)+len(payload))
	wire = append(wire, protocolHeaderBytes...)
	wire = append(wire, payload...)

	log.HexDebug(wire)
	if err := sess.Transmit(wire); err != nil {
		return nil, fmt.Errorf("im: transmit WriteRequest: %w", err)
	}

	responseRaw, err := receiveExchangeResponse(sess, exchangeID)
	if err != nil {
		return nil, fmt.Errorf("im: receive WriteResponse: %w", err)
	}

	return parseWriteResponse(responseRaw)
}

// buildWriteRequestPayload encodes the WriteRequest TLV payload for a single
// attribute path. See WriteAttribute for the wire layout.
func buildWriteRequestPayload(endpointID EndpointID, clusterID ClusterID, attributeID AttributeID, encodeData func(enc tlv.Encoder) error) ([]byte, error) {
	if encodeData == nil {
		return nil, fmt.Errorf("im: WriteAttribute: encodeData must not be nil")
	}

	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())

	enc.PutBool(tlv.NewContextTag(0), false) // suppress-response
	enc.PutBool(tlv.NewContextTag(1), false) // timed-request

	enc.BeginArray(tlv.NewContextTag(2)) // write-requests

	enc.BeginStructure(tlv.NewAnonymousTag()) // attribute-data-IB

	enc.BeginList(tlv.NewContextTag(1)) // attribute-path-IB
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

	if err := encodeData(enc); err != nil {
		return nil, fmt.Errorf("im: encode attribute Data: %w", err)
	}

	if err := enc.EndContainer(); err != nil { // end attribute-data-IB
		return nil, err
	}
	if err := enc.EndContainer(); err != nil { // end write-requests
		return nil, err
	}

	// Tag 3: MoreChunkedMessages. Included defensively (false), mirroring
	// ReadRequestMessage's IsFabricFiltered/InteractionModelRevision
	// real-device quirks (see buildReadRequestPayload) — UNVERIFIED against
	// a real device or mattertest/mockdevice for WriteRequestMessage
	// specifically.
	enc.PutBool(tlv.NewContextTag(3), false)

	enc.PutUnsigned1(tlv.NewContextTag(interactionModelRevisionTag), interactionModelRevision)

	if err := enc.EndContainer(); err != nil { // end top-level structure
		return nil, err
	}
	return enc.Bytes(), nil
}

// parseWriteResponse parses the decrypted payload of a WriteResponse
// message, walking its nested structure to extract the StatusIB of the
// first AttributeStatusIB (this client only ever writes one attribute path
// per WriteRequestMessage, see buildWriteRequestPayload).
// 10.7.5. WriteResponseMessage.
func parseWriteResponse(data []byte) (*WriteResponse, error) {
	protHdr, err := message.NewProtocolHeaderFromBytes(data)
	if err != nil {
		return nil, fmt.Errorf("im: parse protocol header: %w", err)
	}
	protoHdrBytes, err := protHdr.Bytes()
	if err != nil {
		return nil, fmt.Errorf("im: re-serialize protocol header: %w", err)
	}
	if len(data) <= len(protoHdrBytes) {
		return nil, fmt.Errorf("im: WriteResponse missing payload")
	}
	tlvData := data[len(protoHdrBytes):]

	// A device rejecting the whole WriteRequestMessage replies with a
	// StatusResponseMessage instead of a WriteResponseMessage — same failure
	// mode as ReadRequestMessage/InvokeRequestMessage, see the matching
	// comment in parseReadResponseCore.
	if protHdr.Opcode().IsStatusResponseMessage() {
		status, err := parseStatusResponseMessage(tlvData)
		if err != nil {
			return nil, fmt.Errorf("im: WriteResponse: %w", err)
		}
		return &WriteResponse{Status: status}, nil
	}

	dec := tlv.NewDecoderWithBytes(tlvData)
	if !dec.Next() {
		if err := dec.Error(); err != nil {
			return nil, fmt.Errorf("im: WriteResponse: %w", err)
		}
		return nil, fmt.Errorf("im: WriteResponse: empty payload")
	}
	if !dec.Element().Type().IsStructure() {
		return nil, fmt.Errorf("im: WriteResponse: expected top-level Structure")
	}

	resp := &WriteResponse{}
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
		case 0: // write-responses (AttributeStatusIB array)
			if !elem.Type().IsList() && !elem.Type().IsArray() {
				return nil, fmt.Errorf("im: WriteResponse: write-responses is not a list")
			}
			if err := parseAttributeStatusIBsCore(dec, resp, &found); err != nil {
				return nil, fmt.Errorf("im: WriteResponse: %w", err)
			}
		default:
			if elem.Type().IsStructure() || elem.Type().IsList() || elem.Type().IsArray() {
				if err := skipContainer(dec); err != nil {
					return nil, fmt.Errorf("im: WriteResponse: %w", err)
				}
			}
		}
	}
	if err := dec.Error(); err != nil {
		return nil, fmt.Errorf("im: WriteResponse: %w", err)
	}
	if !found {
		return nil, fmt.Errorf("im: WriteResponse: no attribute status for requested path")
	}
	return resp, nil
}

// parseAttributeStatusIBsCore decodes the elements of the write-responses
// list, assuming the caller has already consumed the List/Array-begin
// marker. Only the first AttributeStatusIB is parsed into resp; any further
// ones are skipped. Reuses parseAttributeStatusIBCore (read_impl.go), which
// decodes the same AttributeStatusIB shape (10.6.5) used here.
func parseAttributeStatusIBsCore(dec tlv.Decoder, resp *WriteResponse, found *bool) error {
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			return dec.Error()
		}
		if !elem.Type().IsStructure() {
			return fmt.Errorf("attribute-status-IB is not a structure")
		}
		if *found {
			if err := skipContainer(dec); err != nil {
				return err
			}
			continue
		}
		status, err := parseAttributeStatusIBCore(dec)
		if err != nil {
			return err
		}
		if status != nil {
			resp.Status = *status
		}
		*found = true
	}
	return dec.Error()
}
