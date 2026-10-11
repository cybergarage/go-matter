// Copyright (C) 2026 The go-matter Authors. Licensed under the Apache License, Version 2.0.

package im

import (
	"fmt"

	"github.com/cybergarage/go-matter/matter/encoding/message"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
)

// ReadValueAttribute reads one concrete path and retains scalar or structured
// Data. It validates the whole response and path before publishing a value.
// List append reports within one message are reassembled only when ListIndex is
// explicitly Null. Cross-message chunking and indexed list updates are rejected;
// callers never receive a partial value. The legacy scalar/streaming APIs remain
// unchanged. 10.6.3 AttributeDataIB / 10.5.4.3 List Chunking.
func ReadValueAttribute(sess SecureSession, endpointID EndpointID, clusterID ClusterID, attributeID AttributeID) (*ValueReadResponse, error) {
	data, err := doReadRequest(sess, endpointID, clusterID, attributeID)
	if err != nil {
		return nil, err
	}
	return parseValueReadResponse(data, endpointID, clusterID, attributeID)
}

// readValueTree consumes a complete TLV subtree, including its end marker.
func readValueTree(dec tlv.Decoder, elem tlv.Element, depth int, count *int) (*AttributeValue, error) {
	*count++
	if depth > MaxValueReadDepth || *count > MaxValueReadElements {
		return nil, fmt.Errorf("im: value read depth/element limit exceeded")
	}
	v := &AttributeValue{Element: elem}
	if !elem.Type().IsContainer() {
		return v, nil
	}
	seen := map[string]bool{}
	for dec.Next() {
		child := dec.Element()
		if child.Type().IsEndOfContainer() {
			if child.Tag().Control() != tlv.TagAnonymous {
				return nil, fmt.Errorf("im: tagged EndOfContainer")
			}
			return v, nil
		}
		if elem.Type().IsArray() && child.Tag().Control() != tlv.TagAnonymous {
			return nil, fmt.Errorf("im: array item is not anonymous")
		}
		if elem.Type().IsStructure() {
			if child.Tag().Control() == tlv.TagAnonymous {
				return nil, fmt.Errorf("im: anonymous structure field")
			}
			key := fmt.Sprintf("%d:%x", child.Tag().Control(), child.Tag().Bytes())
			if seen[key] {
				return nil, fmt.Errorf("im: duplicate structure field tag")
			}
			seen[key] = true
		}
		nested, err := readValueTree(dec, child, depth+1, count)
		if err != nil {
			return nil, err
		}
		v.Children = append(v.Children, nested)
	}
	if err := dec.Error(); err != nil {
		return nil, fmt.Errorf("im: value read: %w", err)
	}
	return nil, fmt.Errorf("im: unterminated value container")
}

func valueField(v *AttributeValue, tag uint8) *AttributeValue {
	for _, child := range v.Children {
		if ct, ok := child.Element.Tag().(tlv.ContextTag); ok && uint8(ct.ContextNumber()) == tag {
			return child
		}
	}
	return nil
}

func valueUnsigned(v *AttributeValue, max uint64) (uint64, error) {
	if v != nil {
		if n, ok := v.Element.Unsigned(); ok && n <= max {
			return n, nil
		}
	}
	return 0, fmt.Errorf("im: missing or invalid unsigned field")
}

func valueStatus(v *AttributeValue) (*InvokeStatus, error) {
	if v == nil || !v.Element.Type().IsStructure() {
		return nil, fmt.Errorf("im: missing StatusIB")
	}
	n, err := valueUnsigned(valueField(v, 0), 255)
	if err != nil {
		return nil, err
	}
	s := &InvokeStatus{IMStatus: uint8(n)}
	if c := valueField(v, 1); c != nil {
		n, err = valueUnsigned(c, 255)
		if err != nil {
			return nil, err
		}
		s.ClusterStatus = uint8(n)
	}
	return s, nil
}

func valuePath(v *AttributeValue, ep EndpointID, cl ClusterID, attr AttributeID) (bool, error) {
	if v == nil || !v.Element.Type().IsList() {
		return false, fmt.Errorf("im: missing AttributePathIB")
	}
	seen := map[uint8]bool{}
	for _, child := range v.Children {
		tag, ok := child.Element.Tag().(tlv.ContextTag)
		if !ok {
			return false, fmt.Errorf("im: invalid path field tag")
		}
		if seen[uint8(tag.ContextNumber())] {
			return false, fmt.Errorf("im: duplicate path field")
		}
		seen[uint8(tag.ContextNumber())] = true
	}
	for _, field := range []struct {
		tag       uint8
		want, max uint64
	}{
		{2, uint64(ep), 0xffff}, {3, uint64(cl), 0xffffffff}, {4, uint64(attr), 0xffffffff},
	} {
		n, err := valueUnsigned(valueField(v, field.tag), field.max)
		if err != nil || n != field.want {
			return false, fmt.Errorf("im: response path does not match requested attribute")
		}
	}
	if valueField(v, 1) != nil {
		return false, fmt.Errorf("im: node-qualified path unsupported")
	}
	if index := valueField(v, 5); index != nil {
		if !index.Element.Type().IsNull() {
			return false, fmt.Errorf("im: indexed list update unsupported")
		}
		return true, nil
	}
	return false, nil
}

func parseValueReadResponse(data []byte, ep EndpointID, cl ClusterID, attr AttributeID) (*ValueReadResponse, error) {
	if len(data) > MaxValueReadBytes {
		return nil, fmt.Errorf("im: value read byte limit exceeded")
	}
	h, err := message.NewProtocolHeaderFromBytes(data)
	if err != nil {
		return nil, err
	}
	hb, err := h.Bytes()
	if err != nil {
		return nil, err
	}
	if len(hb) > len(data) {
		return nil, fmt.Errorf("im: incomplete protocol header")
	}
	if h.ProtocolID() != message.InteractionModel || (!h.Opcode().IsReportDataMessage() && !h.Opcode().IsStatusResponseMessage()) {
		return nil, fmt.Errorf("im: unexpected value read message")
	}
	dec := tlv.NewDecoderWithBytes(data[len(hb):])
	if !dec.Next() || !dec.Element().Type().IsStructure() || dec.Element().Tag().Control() != tlv.TagAnonymous {
		return nil, fmt.Errorf("im: value read requires top-level anonymous Structure")
	}
	count := 0
	root, err := readValueTree(dec, dec.Element(), 0, &count)
	if err != nil {
		return nil, err
	}
	if dec.More() || dec.Error() != nil {
		return nil, fmt.Errorf("im: trailing value read payload")
	}
	revision, err := valueUnsigned(valueField(root, interactionModelRevisionTag), 255)
	if err != nil || revision == 0 || revision > uint64(interactionModelRevision) {
		return nil, fmt.Errorf("im: missing or unsupported InteractionModelRevision")
	}
	if h.Opcode().IsStatusResponseMessage() {
		n, err := valueUnsigned(valueField(root, 0), 255)
		if err != nil {
			return nil, err
		}
		return &ValueReadResponse{Status: &InvokeStatus{IMStatus: uint8(n)}}, nil
	}
	if chunks := valueField(root, 3); chunks != nil {
		more, ok := chunks.Element.Bool()
		if !ok || more {
			return nil, fmt.Errorf("im: cross-message chunked value read unsupported")
		}
	}
	reports := valueField(root, 1)
	if reports == nil || (!reports.Element.Type().IsArray() && !reports.Element.Type().IsList()) || len(reports.Children) == 0 {
		return nil, fmt.Errorf("im: missing attribute reports")
	}
	resp := &ValueReadResponse{}
	var version *uint64
	for _, report := range reports.Children {
		if !report.Element.Type().IsStructure() {
			return nil, fmt.Errorf("im: invalid AttributeReportIB")
		}
		d, s := valueField(report, 1), valueField(report, 0)
		if (d == nil) == (s == nil) {
			return nil, fmt.Errorf("im: ambiguous or empty AttributeReportIB")
		}
		if s != nil {
			if !s.Element.Type().IsStructure() {
				return nil, fmt.Errorf("im: invalid AttributeStatusIB")
			}
			if _, err := valuePath(valueField(s, 0), ep, cl, attr); err != nil {
				return nil, err
			}
			status, err := valueStatus(valueField(s, 1))
			if err != nil {
				return nil, err
			}
			resp.Status = status
			continue
		}
		if !d.Element.Type().IsStructure() {
			return nil, fmt.Errorf("im: invalid AttributeDataIB")
		}
		appendItem, err := valuePath(valueField(d, 1), ep, cl, attr)
		if err != nil {
			return nil, err
		}
		var currentVersion *uint64
		if field := valueField(d, 0); field != nil {
			n, err := valueUnsigned(field, 0xffffffff)
			if err != nil {
				return nil, err
			}
			currentVersion = &n
		}
		if resp.Value != nil && ((version == nil) != (currentVersion == nil) || (version != nil && currentVersion != nil && *version != *currentVersion)) {
			return nil, fmt.Errorf("im: inconsistent list DataVersion")
		}
		version = currentVersion
		v := valueField(d, 2)
		if v == nil {
			return nil, fmt.Errorf("im: missing attribute Data")
		}
		if resp.Value == nil {
			if appendItem {
				return nil, fmt.Errorf("im: append without initial list value")
			}
			resp.Value = v
		} else {
			if !appendItem || (!resp.Value.Element.Type().IsArray() && !resp.Value.Element.Type().IsList()) {
				return nil, fmt.Errorf("im: multiple whole attribute values")
			}
			// Retain the append report's original Data tag; do not manufacture an anonymous tag.
			resp.Value.Children = append(resp.Value.Children, v)
		}
	}
	if resp.Status != nil {
		resp.Value = nil
	}
	if resp.Status == nil && resp.Value == nil {
		return nil, fmt.Errorf("im: no observed value")
	}
	return resp, nil
}
