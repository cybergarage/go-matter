// Copyright (C) 2026 The go-matter Authors. Licensed under the Apache License, Version 2.0.

package tui

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/cybergarage/go-matter/matter"
	"github.com/cybergarage/go-matter/matter/datamodel"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	"github.com/cybergarage/go-matter/matter/protocol/im"
)

const boolKind = "bool"
const signedKind = "signed"
const unsignedKind = "unsigned"
const trueText = "true"

type settingKey struct {
	node      uint64
	endpoint  im.EndpointID
	cluster   im.ClusterID
	attribute im.AttributeID
}

type editValue struct {
	kind     string
	null     bool
	boolean  bool
	signed   int64
	unsigned uint64
}
type inputSchema struct {
	kind     string
	bits     int
	nullable bool
	min      int64
	max      int64
	umin     uint64
	umax     uint64
	choices  map[string]uint64
}

func parseUnsigned(s string, bits int) (uint64, error) {
	base := 10
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		base = 16
		s = s[2:]
	}
	return strconv.ParseUint(s, base, bits)
}
func parseSigned(s string, bits int) (int64, error) {
	base := 10
	sign := ""
	if strings.HasPrefix(s, "-") {
		sign = "-"
		s = s[1:]
	}
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		base = 16
		s = s[2:]
	}
	return strconv.ParseInt(sign+s, base, bits)
}
func schemaForAttribute(a datamodel.Attribute, cl im.ClusterID) (inputSchema, error) {
	s := inputSchema{nullable: a.Nullable}
	if !a.Writable {
		return s, errors.New("readonly attribute; use the separate On/Off Invoke menu for power")
	}
	if a.Definition.Property("mustUseTimedWrite") == trueText || a.Definition.Property("mustUseTimedInvoke") == trueText {
		return s, errors.New("TimedWrite required; not supported by this editor")
	}
	if a.Definition.Property("constraint") != "" {
		return s, errors.New("unevaluated type constraint; SET disabled")
	}
	t, ok := dictionary.Type(a.Type, cl)
	if !ok {
		return s, errors.New("unknown type; SET disabled")
	}
	if a.Type == "boolean" {
		s.kind = boolKind
		return s, nil
	}
	switch t.Kind {
	case "enum":
		s.kind = unsignedKind
		base, found := dictionary.Type(t.Definition.Property("type"), cl)
		if !found {
			return s, errors.New("unknown enum base")
		}
		s.bits, _ = strconv.Atoi(base.Definition.Property("size"))
		s.bits *= 8
		s.choices = map[string]uint64{}
		for _, item := range t.Definition.NamedChildren("item") {
			value, err := parseUnsigned(item.Property("value"), 64)
			if err != nil {
				return s, errors.New("unresolved enum entry")
			}
			s.choices[item.Property("name")] = value
		}
		if len(s.choices) == 0 {
			return s, errors.New("enum values unavailable")
		}
	case "atomic":
		s.bits, _ = strconv.Atoi(t.Definition.Property("size"))
		s.bits *= 8
		switch {
		case t.Definition.Property("signed") == trueText:
			s.kind = signedKind
		case strings.HasPrefix(a.Type, "int") && strings.HasSuffix(a.Type, "u"):
			s.kind = unsignedKind
		default:
			return s, errors.New("unsupported scalar type; SET disabled")
		}
	default:
		return s, errors.New("unknown structure/bitmap; SET disabled")
	}
	if s.bits != 8 && s.bits != 16 && s.bits != 32 && s.bits != 64 {
		return s, errors.New("unsupported storage width")
	}
	if s.kind == signedKind {
		s.min = math.MinInt64
		s.max = math.MaxInt64
		if s.bits < 64 {
			s.min = -(int64(1) << (s.bits - 1))
			s.max = (int64(1) << (s.bits - 1)) - 1
		}
		if v := a.Definition.Property("min"); v != "" {
			n, err := parseSigned(v, 64)
			if err != nil || n < s.min {
				return s, errors.New("unresolved signed minimum")
			}
			s.min = n
		}
		if v := a.Definition.Property("max"); v != "" {
			n, err := parseSigned(v, 64)
			if err != nil || n > s.max {
				return s, errors.New("unresolved signed maximum")
			}
			s.max = n
		}
		if s.min > s.max {
			return s, errors.New("invalid signed range")
		}
	} else {
		s.umax = math.MaxUint64
		if s.bits < 64 {
			s.umax = (uint64(1) << s.bits) - 1
		}
		if v := a.Definition.Property("min"); v != "" {
			n, err := parseUnsigned(v, 64)
			if err != nil {
				return s, errors.New("unresolved unsigned minimum")
			}
			s.umin = n
		}
		if v := a.Definition.Property("max"); v != "" {
			n, err := parseUnsigned(v, 64)
			if err != nil || n > s.umax {
				return s, errors.New("unresolved unsigned maximum")
			}
			s.umax = n
		}
		if s.umin > s.umax {
			return s, errors.New("invalid unsigned range")
		}
	}
	return s, nil
}
func writableSchema(p Path) (inputSchema, error) {
	s := inputSchema{}
	if p.Kind != "" {
		return s, errors.New("select an observed attribute")
	}
	if p.Cluster == 0x101 {
		return s, errors.New("door lock and credential operations are excluded")
	}
	a, ok := attributeDefinition(p)
	if !ok {
		return s, errors.New("definition unavailable")
	}
	if !a.Writable {
		return s, errors.New("readonly attribute; OnOff uses separate Invoke, never Write")
	}
	if p.Cluster != 6 || p.Attribute < 0x4001 || p.Attribute > 0x4003 {
		return s, errors.New("outside the initial On/Off configuration allowlist")
	}
	cl, ok := dictionary.Cluster(p.Cluster)
	if !ok || p.ObservedRevision == nil || *p.ObservedRevision != cl.Revision {
		return s, errors.New("cluster revision unverified or mismatched")
	}
	if p.ObservedFeatures != nil && *p.ObservedFeatures & ^uint32(7) != 0 {
		return s, errors.New("unknown feature bits; conditions not evaluated")
	}
	if p.ObservedFeatures == nil {
		return s, errors.New("FeatureMap unavailable")
	}
	// Only the audited single LT term is evaluated. Other conditions fail closed.
	for _, condition := range a.Definition.Children {
		if strings.HasSuffix(condition.Name, "Conform") {
			if condition.Name != "mandatoryConform" || len(condition.Children) != 1 || condition.Children[0].Name != "feature" || condition.Children[0].Property("name") != "LT" {
				return s, errors.New("unevaluated conformance condition")
			}
			if *p.ObservedFeatures&1 == 0 || *p.ObservedFeatures&4 != 0 {
				return s, errors.New("lighting feature absent or incompatible OffOnly feature present")
			}
		}
	}
	return schemaForAttribute(a, p.Cluster)
}
func (s inputSchema) parse(text string) (editValue, error) {
	v := editValue{kind: s.kind}
	text = strings.TrimSpace(text)
	if strings.EqualFold(text, "null") {
		if !s.nullable {
			return v, errors.New("null is not permitted")
		}
		v.null = true
		return v, nil
	}
	switch s.kind {
	case boolKind:
		if text != trueText && text != "false" {
			return v, errors.New("enter true or false")
		}
		v.boolean = text == trueText
	case signedKind:
		n, err := parseSigned(text, s.bits)
		if err != nil || n < s.min || n > s.max {
			return v, fmt.Errorf("enter a signed value in [%d, %d]", s.min, s.max)
		}
		v.signed = n
	case unsignedKind:
		var n uint64
		var err error
		found := false
		for name, value := range s.choices {
			if strings.EqualFold(name, text) {
				n = value
				found = true
				break
			}
		}
		if !found {
			n, err = parseUnsigned(text, s.bits)
		}
		if err != nil || n < s.umin || n > s.umax {
			return v, fmt.Errorf("enter an unsigned value in [%d, %d]", s.umin, s.umax)
		}
		if len(s.choices) > 0 {
			known := false
			for _, value := range s.choices {
				known = known || value == n
			}
			if !known {
				return v, errors.New("select a declared enum value")
			}
		}
		v.unsigned = n
	default:
		return v, errors.New("unsupported input schema")
	}
	return v, nil
}
func (v editValue) String() string {
	if v.null {
		return "null"
	}
	switch v.kind {
	case boolKind:
		return strconv.FormatBool(v.boolean)
	case signedKind:
		return strconv.FormatInt(v.signed, 10)
	default:
		return strconv.FormatUint(v.unsigned, 10)
	}
}
func (v editValue) encode(e tlv.Encoder) error {
	tag := tlv.NewContextTag(2)
	if v.null {
		e.PutNull(tag)
		return nil
	}
	switch v.kind {
	case boolKind:
		e.PutBool(tag, v.boolean)
		return nil
	case signedKind:
		return e.PutSigned(tag, v.signed)
	case unsignedKind:
		return e.PutUnsigned(tag, v.unsigned)
	}
	return errors.New("invalid edit value")
}
func (v editValue) matches(e tlv.Element) bool {
	if v.null {
		return e.Type() == tlv.Null
	}
	switch v.kind {
	case boolKind:
		n, ok := e.Bool()
		return ok && n == v.boolean
	case signedKind:
		n, ok := e.Signed()
		return ok && n == v.signed
	case unsignedKind:
		n, ok := e.Unsigned()
		return ok && n == v.unsigned
	}
	return false
}

// Optional boundary avoids adding a write operation to unrelated fake backends.
type setBackend interface {
	Set(context.Context, uint64, Path, editValue) (Result, error)
}

func writeNode(ctx context.Context, n matter.Node, p Path, v editValue) (Result, error) {
	s, err := writableSchema(p)
	if err != nil {
		return Result{}, err
	}
	canonical, err := s.parse(v.String())
	if err != nil || canonical != v {
		return Result{}, errors.New("invalid typed edit")
	}
	if err = ctx.Err(); err != nil {
		return Result{}, err
	}
	ack, err := n.WriteAttribute(p.Endpoint, p.Cluster, p.Attribute, v.encode)
	if err != nil || ack == nil {
		return Result{}, errors.New("WRITE outcome UNKNOWN; do not automatically retry or claim rollback")
	}
	if !ack.IsSuccess() {
		return Result{}, errors.New("WRITE REJECTED / " + statusLabel(&ack.Status))
	}
	result := Result{Acknowledged: true, Message: "WRITE ACKNOWLEDGED: " + pathLabel(p) + " = " + v.String()}
	if ctx.Err() != nil {
		result.Message += "\nFresh GET UNKNOWN: canceled/timeout after ACK; no automatic retry or rollback"
		return result, nil //nolint:nilerr // ACK is known; canceled readback is explicitly UNKNOWN.
	}
	read, err := n.ReadAttribute(p.Endpoint, p.Cluster, p.Attribute)
	at := time.Now()
	if err != nil || read == nil || read.Status != nil || read.Value == nil || ctx.Err() != nil {
		result.Message += "\nFresh GET UNKNOWN: failed/rejected/canceled; no verified value, no rollback"
		if read != nil && read.Status != nil {
			result.Message += "\n" + statusLabel(read.Status)
		}
		return result, nil //nolint:nilerr
	}
	actual, raw, decoded := scalarValue(read.Value, p)
	verdict := "MISMATCH"
	if !decoded {
		verdict = "UNKNOWN"
	} else if v.matches(read.Value) {
		verdict = "MATCH"
	}
	result.Message += "\n" + observationMessage(p, actual, raw, "FRESH GET "+verdict, at)
	return result, nil
}
func refreshSetPath(reader inventoryReader, p Path) (Path, error) {
	if _, err := writableSchema(p); err != nil {
		return p, err
	}
	attrs, err := reader.ids(p.Endpoint, p.Cluster, 0xFFFB)
	if err != nil {
		return p, errors.New("fresh AttributeList unavailable; SET disabled")
	}
	found := false
	for _, id := range attrs {
		found = found || im.AttributeID(id) == p.Attribute
	}
	if !found {
		return p, errors.New("attribute no longer advertised; SET disabled")
	}
	revision, re := reader.scalar(p.Endpoint, p.Cluster, 0xFFFD)
	features, fe := reader.scalar(p.Endpoint, p.Cluster, 0xFFFC)
	if re != nil || fe != nil || revision > 0xFFFF || features > 0xFFFFFFFF {
		return p, errors.New("fresh revision/feature unavailable; SET disabled")
	}
	rev := uint16(revision)
	fm := uint32(features)
	p.ObservedRevision = &rev
	p.ObservedFeatures = &fm
	if _, err := writableSchema(p); err != nil {
		return p, err
	}
	return p, nil
}
func (b *Live) Set(ctx context.Context, id uint64, p Path, v editValue) (Result, error) {
	if _, err := writableSchema(p); err != nil {
		return Result{}, err
	}
	return b.withNode(ctx, id, func(n matter.Node) (Result, error) {
		fresh, err := refreshSetPath(nodeInventoryReader{n}, p)
		if err != nil {
			return Result{}, err
		}
		return writeNode(ctx, n, fresh, v)
	})
}
func (b *Demo) Set(ctx context.Context, id uint64, p Path, v editValue) (Result, error) {
	s, err := writableSchema(p)
	if err != nil {
		return Result{}, err
	}
	canonical, err := s.parse(v.String())
	if err != nil || canonical != v {
		return Result{}, errors.New("invalid fixture edit")
	}
	if err = ctx.Err(); err != nil {
		return Result{}, err
	}
	if b.settings == nil {
		b.settings = map[settingKey]editValue{}
	}
	b.settings[settingKey{node: id, endpoint: p.Endpoint, cluster: p.Cluster, attribute: p.Attribute}] = v
	enc := tlv.NewEncoder()
	_ = v.encode(enc)
	dec := tlv.NewDecoderWithBytes(enc.Bytes())
	dec.Next()
	actual, raw, _ := scalarValue(dec.Element(), p)
	return Result{Acknowledged: true, Message: "OFFLINE FIXTURE / WRITE ACKNOWLEDGED: " + pathLabel(p) + " = " + v.String() + "\n" + observationMessage(p, actual, raw, "OFFLINE FIXTURE / FRESH GET MATCH", time.Now()) + "\nFictional state only; no device, credential or network."}, nil
}
