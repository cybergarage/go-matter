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

	"github.com/cybergarage/go-matter/matter/encoding/message"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
)

// Invoke sends an InvokeRequest IM message over the given secure session and waits
// for an InvokeResponse. commandFields may be nil for commands with no fields.
//
// InvokeRequest TLV layout (spec section 10.7.9):
//
//	invoke-request-message => STRUCTURE {
//	  0: suppress-response  [BOOL]
//	  1: timed-request      [BOOL]
//	  2: invoke-requests    [LIST] {
//	    command-data-IB => STRUCTURE {
//	      0: command-path-IB => STRUCTURE {
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
	protocolHeaderBytes, err := buildIMProtocolHeader(message.InvokeRequestMessage)
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
	responseRaw, err := sess.Receive()
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

	// Tag 2: invoke-requests (list).
	enc.BeginList(tlv.NewContextTag(2))

	// command-data-IB structure.
	enc.BeginStructure(tlv.NewAnonymousTag())

	// Tag 0: command-path-IB structure.
	enc.BeginStructure(tlv.NewContextTag(0))
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

	// Tag 1: command-fields (optional raw TLV structure bytes).
	if len(commandFields) > 0 {
		if err := enc.PutOctet(tlv.NewContextTag(1), commandFields); err != nil {
			return nil, err
		}
	}

	if err := enc.EndContainer(); err != nil { // end command-data-IB
		return nil, err
	}
	if err := enc.EndContainer(); err != nil { // end invoke-requests list
		return nil, err
	}
	if err := enc.EndContainer(); err != nil { // end top-level structure
		return nil, err
	}

	return enc.Bytes(), nil
}

// buildIMProtocolHeader builds the Matter protocol header bytes for an IM message.
func buildIMProtocolHeader(opcode message.Opcode) ([]byte, error) {
	hdr := message.NewProtocolHeader(
		message.WithHeaderExchangeFlags(message.InitiatorFlag|message.ReliabilityFlag),
		message.WithHeaderOpcode(opcode),
		message.WithHeaderExchangeID(message.NewFirstExchangeID()),
		message.WithHeaderProtocolID(message.InteractionModel),
	)
	return hdr.Bytes()
}

// parseInvokeResponse parses the decrypted payload of an InvokeResponse message.
// It scans for IM status codes embedded in the response TLV.
// 10.7.17. InvokeResponseMessage.
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

	// Linearly scan all TLV elements looking for IM/cluster status codes.
	// In InvokeResponseMessage, status codes are context tags 0 and 1 inside a status-IB structure.
	// Rather than full structural parsing, we scan all uint8 elements for the two status fields.
	resp := &InvokeResponse{}
	dec := tlv.NewDecoderWithBytes(tlvData)
	for dec.Next() {
		elem := dec.Element()
		ctxTag, ok := elem.Tag().(tlv.ContextTag)
		if !ok {
			continue
		}
		switch ctxTag.ContextNumber() {
		case 0:
			// IM status (context 0 inside status-IB) or suppress-response (top-level context 0, bool).
			if v, ok2 := elem.Unsigned1(); ok2 {
				resp.Status.IMStatus = v
			}
		case 1:
			// Cluster status (context 1 inside status-IB).
			if v, ok2 := elem.Unsigned1(); ok2 {
				resp.Status.ClusterStatus = v
			}
		}
	}

	return resp, nil
}
