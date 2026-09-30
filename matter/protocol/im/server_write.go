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

	"github.com/cybergarage/go-matter/matter/encoding/message"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
)

// AttributeWriteRequest is the write of one attribute, as an
// AttributeWriteHandler receives it.
type AttributeWriteRequest struct {
	// Session is the session the write arrived on.
	Session SecureSession
	// Path is the attribute written.
	Path AttributePath
	// Data is the value written, one TLV element with an anonymous tag,
	// which Decoder decodes.
	Data []byte
	// Append reports whether the write appends Data to a list attribute
	// (a ListIndex of null) rather than replacing the attribute (10.6.2).
	Append bool
	// Timed reports whether the write arrived in a timed interaction.
	Timed bool
}

// Decoder returns a decoder positioned on the written value.
func (r *AttributeWriteRequest) Decoder() (tlv.Decoder, tlv.Element, error) {
	dec := tlv.NewDecoderWithBytes(r.Data)
	if !dec.Next() {
		if err := dec.Error(); err != nil {
			return nil, nil, err
		}
		return nil, nil, errors.New("im: empty attribute data")
	}
	return dec, dec.Element(), nil
}

// AttributeWriteHandler writes an attribute, and returns the status the
// write is answered with.
type AttributeWriteHandler func(req *AttributeWriteRequest) Status

type writeEntry struct {
	handler   AttributeWriteHandler
	privilege Privilege
}

// DefaultWritePrivilege is the privilege writing an attribute requires
// unless WithPrivilege says otherwise (9.10.5.2).
const DefaultWritePrivilege = PrivilegeOperate

// HandleAttributeWrite registers h for writes of an attribute, replacing
// any previous one. It requires DefaultWritePrivilege unless WithPrivilege
// says otherwise. An attribute written without one is answered with
// StatusUnsupportedWrite.
func (s *Server) HandleAttributeWrite(endpoint EndpointID, cluster ClusterID, attribute AttributeID, h AttributeWriteHandler, opts ...HandlerOption) {
	o := newHandlerOptions(DefaultWritePrivilege, opts)
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.writes[AttributePath{Endpoint: endpoint, Cluster: cluster, Attribute: attribute}] = writeEntry{handler: h, privilege: o.privilege}
	s.ensureGlobalAttributesLocked(endpoint, cluster)
}

// writeRequest is one AttributeDataIB of a WriteRequestMessage.
type writeRequest struct {
	path   requestedPath
	append bool
	data   []byte
}

// decodeWriteRequest decodes a WriteRequestMessage (10.7.6).
func decodeWriteRequest(body []byte) ([]writeRequest, bool, error) {
	dec, err := openTopLevel(body)
	if err != nil {
		return nil, false, err
	}
	var writes []writeRequest
	timed := false
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			break
		}
		tag, _ := contextNumber(elem)
		switch {
		case tag == 1 && !elem.Type().IsContainer():
			timed, _ = elem.Bool()
		case tag == 2 && elem.Type().IsArray():
			for dec.Next() {
				ib := dec.Element()
				if ib.Type().IsEndOfContainer() {
					break
				}
				if !ib.Type().IsStructure() {
					return nil, false, errors.New("attribute-data-IB is not a structure")
				}
				w, err := decodeAttributeDataIB(dec)
				if err != nil {
					return nil, false, err
				}
				writes = append(writes, w)
			}
		case elem.Type().IsContainer():
			if err := skipContainer(dec); err != nil {
				return nil, false, err
			}
		}
	}
	return writes, timed, dec.Error()
}

func decodeAttributeDataIB(dec tlv.Decoder) (writeRequest, error) {
	var w writeRequest
	hasPath := false
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			if !hasPath || w.data == nil {
				return w, errors.New("attribute-data-IB without a path or data")
			}
			return w, dec.Error()
		}
		tag, _ := contextNumber(elem)
		switch tag {
		case 1:
			if !elem.Type().IsContainer() {
				return w, errors.New("attribute-path-IB is not a list")
			}
			p, appendItem, err := decodeWritePath(dec)
			if err != nil {
				return w, err
			}
			w.path = p
			w.append = appendItem
			hasPath = true
		case 2:
			enc := tlv.NewEncoder()
			if err := copyElement(dec, elem, enc, tlv.NewAnonymousTag()); err != nil {
				return w, err
			}
			w.data = enc.Bytes()
		default:
			if elem.Type().IsContainer() {
				if err := skipContainer(dec); err != nil {
					return w, err
				}
			}
		}
	}
	return w, errors.New("unterminated attribute-data-IB")
}

// decodeWritePath decodes the AttributePathIB of a write, which may carry
// a ListIndex; a null one appends to the list (10.6.2).
func decodeWritePath(dec tlv.Decoder) (requestedPath, bool, error) {
	var p requestedPath
	appendItem := false
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			return p, appendItem, dec.Error()
		}
		tag, _ := contextNumber(elem)
		if tag == 5 && elem.Type().IsNull() {
			appendItem = true
			continue
		}
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
	return p, false, errors.New("unterminated attribute-path-IB")
}

// copyElement encodes elem, and the contents of a container, with tag.
func copyElement(dec tlv.Decoder, elem tlv.Element, enc tlv.Encoder, tag tlv.Tag) error {
	t := elem.Type()
	switch {
	case t.IsStructure(), t.IsArray(), t.IsList():
		switch {
		case t.IsStructure():
			enc.BeginStructure(tag)
		case t.IsArray():
			enc.BeginArray(tag)
		default:
			enc.BeginList(tag)
		}
		for dec.Next() {
			child := dec.Element()
			if child.Type().IsEndOfContainer() {
				return enc.EndContainer()
			}
			if err := copyElement(dec, child, enc, child.Tag()); err != nil {
				return err
			}
		}
		if err := dec.Error(); err != nil {
			return err
		}
		return errors.New("unterminated container")
	case t.IsSignedInt():
		v, _ := elem.Signed()
		return enc.PutSigned(tag, v)
	case t.IsUnsignedInt():
		v, _ := elem.Unsigned()
		return enc.PutUnsigned(tag, v)
	case t.IsBool():
		v, _ := elem.Bool()
		enc.PutBool(tag, v)
	case t.IsFloat32():
		v, _ := elem.Float()
		enc.PutFloat32(tag, float32(v))
	case t.IsFloat64():
		v, _ := elem.Float()
		enc.PutFloat64(tag, v)
	case t.IsUTF8String():
		v, _ := elem.UTF8()
		return enc.PutUTF8(tag, v)
	case t.IsOctetString():
		v, _ := elem.Bytes()
		return enc.PutOctet(tag, v)
	case t.IsNull():
		enc.PutNull(tag)
	default:
		return fmt.Errorf("unsupported TLV element type %v", t)
	}
	return nil
}

func (s *Server) writeHandler(p AttributePath) (writeEntry, bool) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	e, ok := s.writes[p]
	return e, ok
}

// serveWrite answers a WriteRequestMessage with a WriteResponseMessage
// (10.7.7). Only concrete paths are written; a wildcard path is answered
// with StatusInvalidAction.
func (s *Server) serveWrite(sess SecureSession, exchange message.ExchangeID, body []byte) error {
	writes, timed, err := decodeWriteRequest(body)
	if err != nil {
		if sendErr := sendStatusResponse(sess, exchange, StatusInvalidAction); sendErr != nil {
			return sendErr
		}
		return &decodeError{fmt.Errorf("im: decode WriteRequest: %w", err)}
	}
	reports := make([]attributeReport, 0, len(writes))
	for _, w := range writes {
		path := w.path.concretePath()
		status := s.write(sess, w, timed)
		reports = append(reports, attributeReport{path: path, status: status, read: nil})
	}
	payload, err := encodeWriteResponse(reports)
	if err != nil {
		return err
	}
	return sendIMResponse(sess, exchange, message.WriteResponseMessage, payload)
}

func (s *Server) write(sess SecureSession, w writeRequest, timed bool) Status {
	if !w.path.concrete() {
		return StatusInvalidAction
	}
	path := w.path.concretePath()
	entry, ok := s.writeHandler(path)
	if !ok {
		if s.attribute(path).handler != nil {
			return StatusUnsupportedWrite
		}
		_, status := s.expand(w.path)
		if status == StatusSuccess {
			status = StatusUnsupportedAttribute
		}
		return status
	}
	if !s.allowed(sess, path.Endpoint, path.Cluster, entry.privilege) {
		return StatusUnsupportedAccess
	}
	status := entry.handler(&AttributeWriteRequest{Session: sess, Path: path, Data: w.data, Append: w.append, Timed: timed})
	if status == StatusSuccess {
		// A written attribute is reported to the subscriptions covering it.
		s.NotifyAttributeChanged(path)
	}
	return status
}

// encodeWriteResponse encodes a WriteResponseMessage: the status of each
// write.
func encodeWriteResponse(reports []attributeReport) ([]byte, error) {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	enc.BeginArray(tlv.NewContextTag(0)) // write-responses
	for _, r := range reports {
		enc.BeginStructure(tlv.NewAnonymousTag()) // AttributeStatusIB
		if err := encodeAttributePathIB(enc, tlv.NewContextTag(0), r.path); err != nil {
			return nil, err
		}
		if err := encodeStatusIB(enc, tlv.NewContextTag(1), r.status, nil); err != nil {
			return nil, err
		}
		if err := enc.EndContainer(); err != nil {
			return nil, err
		}
	}
	if err := enc.EndContainer(); err != nil {
		return nil, err
	}
	enc.PutUnsigned1(tlv.NewContextTag(interactionModelRevisionTag), interactionModelRevision)
	if err := enc.EndContainer(); err != nil {
		return nil, fmt.Errorf("im: encode WriteResponse: %w", err)
	}
	return enc.Bytes(), nil
}
