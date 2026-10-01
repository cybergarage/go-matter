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
	"errors"
	"fmt"

	"github.com/cybergarage/go-matter/matter/encoding/tlv"
)

// invokeRequest is a decoded InvokeRequestMessage (10.7.9).
type invokeRequest struct {
	suppressResponse bool
	timed            bool
	commands         []*CommandRequest
}

// contextNumber returns the context tag number of elem.
func contextNumber(elem tlv.Element) (uint8, bool) {
	ct, ok := elem.Tag().(tlv.ContextTag)
	if !ok {
		return 0, false
	}
	return uint8(ct.ContextNumber()), true
}

// openTopLevel consumes the anonymous structure every IM message is.
func openTopLevel(body []byte) (tlv.Decoder, error) {
	dec := tlv.NewDecoderWithBytes(body)
	if !dec.Next() || !dec.Element().Type().IsStructure() {
		if err := dec.Error(); err != nil {
			return nil, err
		}
		return nil, errors.New("expected a top-level structure")
	}
	return dec, nil
}

func decodeInvokeRequest(body []byte) (*invokeRequest, error) {
	dec, err := openTopLevel(body)
	if err != nil {
		return nil, err
	}
	req := &invokeRequest{suppressResponse: false, timed: false, commands: nil}
	found := false
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			break
		}
		tag, _ := contextNumber(elem)
		switch {
		case tag == 0 && !elem.Type().IsContainer():
			req.suppressResponse, _ = elem.Bool()
		case tag == 1 && !elem.Type().IsContainer():
			req.timed, _ = elem.Bool()
		case tag == 2 && elem.Type().IsArray():
			commands, err := decodeCommandDataIBs(dec)
			if err != nil {
				return nil, err
			}
			req.commands = commands
			found = true
		case elem.Type().IsContainer():
			if err := skipContainer(dec); err != nil {
				return nil, err
			}
		}
	}
	if err := dec.Error(); err != nil {
		return nil, err
	}
	if !found || len(req.commands) == 0 {
		return nil, errors.New("no command in invoke-requests")
	}
	return req, nil
}

func decodeCommandDataIBs(dec tlv.Decoder) ([]*CommandRequest, error) {
	var commands []*CommandRequest
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			return commands, dec.Error()
		}
		if !elem.Type().IsStructure() {
			return nil, errors.New("command-data-IB is not a structure")
		}
		cmd, err := decodeCommandDataIB(dec)
		if err != nil {
			return nil, err
		}
		commands = append(commands, cmd)
	}
	return nil, errors.New("unterminated invoke-requests")
}

func decodeCommandDataIB(dec tlv.Decoder) (*CommandRequest, error) {
	cmd := &CommandRequest{Fields: map[uint8]tlv.Element{}, Elements: nil, Data: nil}
	hasPath := false
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			if !hasPath {
				return nil, errors.New("command-data-IB has no command-path-IB")
			}
			return cmd, dec.Error()
		}
		tag, _ := contextNumber(elem)
		switch {
		case tag == 0 && elem.Type().IsContainer():
			var err error
			cmd.Endpoint, cmd.Cluster, cmd.Command, err = decodeCommandPathIB(dec)
			if err != nil {
				return nil, err
			}
			hasPath = true
		case tag == 1 && elem.Type().IsStructure():
			if err := decodeCommandFields(dec, cmd); err != nil {
				return nil, err
			}
		case elem.Type().IsContainer():
			if err := skipContainer(dec); err != nil {
				return nil, err
			}
		}
	}
	return nil, errors.New("unterminated command-data-IB")
}

func decodeCommandPathIB(dec tlv.Decoder) (EndpointID, ClusterID, CommandID, error) {
	var endpoint, cluster, command *uint64
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			if endpoint == nil || cluster == nil || command == nil {
				return 0, 0, 0, errors.New("command-path-IB lacks the endpoint, cluster or command")
			}
			return EndpointID(*endpoint), ClusterID(*cluster), CommandID(*command), dec.Error()
		}
		tag, _ := contextNumber(elem)
		v, ok := elem.Unsigned()
		if !ok {
			continue
		}
		switch tag {
		case 0:
			endpoint = &v
		case 1:
			cluster = &v
		case 2:
			command = &v
		}
	}
	return 0, 0, 0, errors.New("unterminated command-path-IB")
}

// decodeCommandFields reads the command-fields structure into cmd: the
// top-level fields by tag, every element in order, and the structure
// re-encoded, for a handler to decode nested fields with.
func decodeCommandFields(dec tlv.Decoder, cmd *CommandRequest) error {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	depth := 1
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			if err := enc.EndContainer(); err != nil {
				return err
			}
			depth--
			if depth == 0 {
				cmd.Data = enc.Bytes()
				return dec.Error()
			}
			continue
		}
		cmd.Elements = append(cmd.Elements, elem)
		if depth == 1 {
			if tag, ok := contextNumber(elem); ok {
				cmd.Fields[tag] = elem
			}
		}
		t := elem.Type()
		switch {
		case t.IsStructure():
			enc.BeginStructure(elem.Tag())
		case t.IsArray():
			enc.BeginArray(elem.Tag())
		case t.IsList():
			enc.BeginList(elem.Tag())
		default:
			if err := copyElement(dec, elem, enc, elem.Tag()); err != nil {
				return err
			}
		}
		if t.IsContainer() {
			depth++
		}
	}
	return errors.New("unterminated command-fields")
}

// requestedPath is an AttributePathIB of a request; a nil field is a
// wildcard (10.6.2).
type requestedPath struct {
	endpoint  *EndpointID
	cluster   *ClusterID
	attribute *AttributeID
}

func (p requestedPath) concrete() bool {
	return p.endpoint != nil && p.cluster != nil && p.attribute != nil
}

// concretePath returns the path of a concrete requested path.
func (p requestedPath) concretePath() AttributePath {
	var ap AttributePath
	if p.endpoint != nil {
		ap.Endpoint = *p.endpoint
	}
	if p.cluster != nil {
		ap.Cluster = *p.cluster
	}
	if p.attribute != nil {
		ap.Attribute = *p.attribute
	}
	return ap
}

// decodeReadRequest decodes a ReadRequestMessage (10.7.2): its attribute
// paths and whether it is fabric-filtered.
func decodeReadRequest(body []byte) ([]requestedPath, bool, error) {
	dec, err := openTopLevel(body)
	if err != nil {
		return nil, false, err
	}
	var paths []requestedPath
	fabricFiltered := false
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			break
		}
		tag, _ := contextNumber(elem)
		switch {
		case tag == 0 && elem.Type().IsArray():
			for dec.Next() {
				pathElem := dec.Element()
				if pathElem.Type().IsEndOfContainer() {
					break
				}
				if !pathElem.Type().IsContainer() {
					return nil, false, errors.New("attribute-path-IB is not a list")
				}
				p, err := decodeAttributePathIB(dec)
				if err != nil {
					return nil, false, err
				}
				paths = append(paths, p)
			}
		case tag == readRequestFabricFilteredTag && !elem.Type().IsContainer():
			fabricFiltered, _ = elem.Bool()
		case elem.Type().IsContainer():
			if err := skipContainer(dec); err != nil {
				return nil, false, err
			}
		}
	}
	return paths, fabricFiltered, dec.Error()
}

// readRequestFabricFilteredTag is the tag of a ReadRequestMessage's
// FabricFiltered field.
const readRequestFabricFilteredTag = 3

func decodeAttributePathIB(dec tlv.Decoder) (requestedPath, error) {
	var p requestedPath
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			return p, dec.Error()
		}
		tag, _ := contextNumber(elem)
		v, ok := elem.Unsigned()
		if !ok {
			continue
		}
		switch tag {
		case 2:
			e := EndpointID(v)
			p.endpoint = &e
		case 3:
			c := ClusterID(v)
			p.cluster = &c
		case 4:
			a := AttributeID(v)
			p.attribute = &a
		}
	}
	return p, errors.New("unterminated attribute-path-IB")
}

// invokeResult is the answer to one command.
type invokeResult struct {
	path   commandPath
	result CommandResult
}

func encodeCommandPathIB(enc tlv.Encoder, p commandPath) error {
	enc.BeginList(tlv.NewContextTag(0))
	enc.PutUnsigned2(tlv.NewContextTag(0), uint16(p.endpoint))
	if err := enc.PutUnsigned(tlv.NewContextTag(1), uint64(p.cluster)); err != nil {
		return err
	}
	if err := enc.PutUnsigned(tlv.NewContextTag(2), uint64(p.command)); err != nil {
		return err
	}
	return enc.EndContainer()
}

func encodeStatusIB(enc tlv.Encoder, tag tlv.Tag, status Status, clusterStatus *uint8) error {
	enc.BeginStructure(tag)
	enc.PutUnsigned1(tlv.NewContextTag(0), uint8(status))
	if clusterStatus != nil {
		enc.PutUnsigned1(tlv.NewContextTag(1), *clusterStatus)
	}
	return enc.EndContainer()
}

// encodeInvokeResponse encodes an InvokeResponseMessage (10.7.10) with one
// InvokeResponseIB per result: a CommandDataIB for a response command, a
// CommandStatusIB otherwise.
func encodeInvokeResponse(results []invokeResult) ([]byte, error) {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	enc.PutBool(tlv.NewContextTag(0), false) // suppress-response
	enc.BeginArray(tlv.NewContextTag(1))     // invoke-responses
	for _, r := range results {
		enc.BeginStructure(tlv.NewAnonymousTag()) // InvokeResponseIB
		if r.result.HasResponse {
			enc.BeginStructure(tlv.NewContextTag(0)) // CommandDataIB
			if err := encodeCommandPathIB(enc, commandPath{r.path.endpoint, r.path.cluster, r.result.ResponseCommand}); err != nil {
				return nil, err
			}
			if 0 < len(r.result.Fields) {
				enc.Raw(r.result.Fields)
			}
		} else {
			enc.BeginStructure(tlv.NewContextTag(1)) // CommandStatusIB
			if err := encodeCommandPathIB(enc, r.path); err != nil {
				return nil, err
			}
			if err := encodeStatusIB(enc, tlv.NewContextTag(1), r.result.Status, r.result.ClusterStatus); err != nil {
				return nil, err
			}
		}
		if err := enc.EndContainer(); err != nil { // CommandDataIB / CommandStatusIB
			return nil, err
		}
		if err := enc.EndContainer(); err != nil { // InvokeResponseIB
			return nil, err
		}
	}
	if err := enc.EndContainer(); err != nil { // invoke-responses
		return nil, err
	}
	enc.PutUnsigned1(tlv.NewContextTag(interactionModelRevisionTag), interactionModelRevision)
	if err := enc.EndContainer(); err != nil {
		return nil, err
	}
	return enc.Bytes(), nil
}

// attributeReport is one AttributeReportIB to send: the value read by read,
// or status when it is not StatusSuccess.
type attributeReport struct {
	path   AttributePath
	status Status
	read   AttributeReader
}

func encodeAttributePathIB(enc tlv.Encoder, tag tlv.Tag, p AttributePath) error {
	enc.BeginList(tag)
	enc.PutUnsigned2(tlv.NewContextTag(2), uint16(p.Endpoint))
	if err := enc.PutUnsigned(tlv.NewContextTag(3), uint64(p.Cluster)); err != nil {
		return err
	}
	if err := enc.PutUnsigned(tlv.NewContextTag(4), uint64(p.Attribute)); err != nil {
		return err
	}
	return enc.EndContainer()
}

// encodeReportData encodes a ReportDataMessage (10.7.3) which answers a
// Read in one message, so it sets SuppressResponse.
func encodeReportData(reports []attributeReport) ([]byte, error) {
	return encodeReportDataMessage(reports, nil, true)
}

// encodeReportDataMessage encodes a ReportDataMessage with the
// subscription it reports for, if any, and whether the receiver answers
// it with a StatusResponse: a subscription's reports ask it to.
func encodeReportDataMessage(reports []attributeReport, subscriptionID *uint32, suppressResponse bool) ([]byte, error) {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	if subscriptionID != nil {
		enc.PutUnsigned4(tlv.NewContextTag(0), *subscriptionID)
	}
	enc.BeginArray(tlv.NewContextTag(1)) // attribute-reports
	for _, r := range reports {
		status := r.status
		var value []byte
		if status == StatusSuccess {
			if r.read == nil {
				status = StatusUnsupportedAttribute
			} else {
				valueEnc := tlv.NewEncoder()
				status = r.read(valueEnc, tlv.NewContextTag(2))
				value = valueEnc.Bytes()
			}
		}
		enc.BeginStructure(tlv.NewAnonymousTag()) // AttributeReportIB
		if status == StatusSuccess {
			enc.BeginStructure(tlv.NewContextTag(1))  // AttributeDataIB
			enc.PutUnsigned4(tlv.NewContextTag(0), 0) // DataVersion
			if err := encodeAttributePathIB(enc, tlv.NewContextTag(1), r.path); err != nil {
				return nil, err
			}
			enc.Raw(value)
		} else {
			enc.BeginStructure(tlv.NewContextTag(0)) // AttributeStatusIB
			if err := encodeAttributePathIB(enc, tlv.NewContextTag(0), r.path); err != nil {
				return nil, err
			}
			if err := encodeStatusIB(enc, tlv.NewContextTag(1), status, nil); err != nil {
				return nil, err
			}
		}
		if err := enc.EndContainer(); err != nil { // AttributeDataIB / AttributeStatusIB
			return nil, err
		}
		if err := enc.EndContainer(); err != nil { // AttributeReportIB
			return nil, err
		}
	}
	if err := enc.EndContainer(); err != nil { // attribute-reports
		return nil, err
	}
	if suppressResponse {
		enc.PutBool(tlv.NewContextTag(4), true) // suppress-response
	}
	enc.PutUnsigned1(tlv.NewContextTag(interactionModelRevisionTag), interactionModelRevision)
	if err := enc.EndContainer(); err != nil {
		return nil, fmt.Errorf("im: encode ReportData: %w", err)
	}
	return enc.Bytes(), nil
}
