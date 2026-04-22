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

// ReadBoolAttribute reads a single boolean attribute over the Interaction Model.
func ReadBoolAttribute(sess SecureSession, endpointID EndpointID, clusterID ClusterID, attributeID AttributeID) (bool, error) {
	payload, err := buildReadRequestPayload(endpointID, clusterID, attributeID)
	if err != nil {
		return false, fmt.Errorf("im: build ReadRequest payload: %w", err)
	}

	protocolHeaderBytes, err := buildIMProtocolHeader(message.ReadRequestMessage)
	if err != nil {
		return false, fmt.Errorf("im: build protocol header: %w", err)
	}

	wire := make([]byte, 0, len(protocolHeaderBytes)+len(payload))
	wire = append(wire, protocolHeaderBytes...)
	wire = append(wire, payload...)

	if err := sess.Transmit(wire); err != nil {
		return false, fmt.Errorf("im: transmit ReadRequest: %w", err)
	}

	responseRaw, err := sess.Receive()
	if err != nil {
		return false, fmt.Errorf("im: receive ReadResponse: %w", err)
	}

	resp, err := parseReadResponse(responseRaw)
	if err != nil {
		return false, err
	}

	dec := tlv.NewDecoderWithBytes(resp.Payload)
	for dec.Next() {
		if v, ok := dec.Element().Bool(); ok {
			return v, nil
		}
	}

	return false, fmt.Errorf("im: ReadResponse missing boolean attribute value")
}

func buildReadRequestPayload(endpointID EndpointID, clusterID ClusterID, attributeID AttributeID) ([]byte, error) {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	enc.BeginArray(tlv.NewContextTag(0))
	enc.BeginList(tlv.NewAnonymousTag())
	enc.PutBool(tlv.NewContextTag(0), false)
	if err := enc.PutUnsigned(tlv.NewContextTag(1), 0); err != nil {
		return nil, err
	}
	enc.PutUnsigned2(tlv.NewContextTag(2), uint16(endpointID))
	if err := enc.PutUnsigned(tlv.NewContextTag(3), uint64(clusterID)); err != nil {
		return nil, err
	}
	if err := enc.PutUnsigned(tlv.NewContextTag(4), uint64(attributeID)); err != nil {
		return nil, err
	}
	enc.PutUnsigned2(tlv.NewContextTag(5), 0)
	if err := enc.PutUnsigned(tlv.NewContextTag(6), 0); err != nil {
		return nil, err
	}
	if err := enc.EndContainer(); err != nil {
		return nil, err
	}
	if err := enc.EndContainer(); err != nil {
		return nil, err
	}
	if err := enc.EndContainer(); err != nil {
		return nil, err
	}
	return enc.Bytes(), nil
}

func parseReadResponse(data []byte) (*ReadResponse, error) {
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
	return &ReadResponse{
		Payload: data[len(protoHdrBytes):],
	}, nil
}
