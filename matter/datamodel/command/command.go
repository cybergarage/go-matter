// Copyright (C) 2026 The go-matter Authors. Licensed under the Apache License, Version 2.0.

// Package command builds the fields of a command request from the datamodel
// catalog: it describes the fields of a command, validates values against
// them, and encodes the CommandFields structure of a CommandDataIB.
//
// The catalog describes a schema, not a device: a command which encodes here
// may still be absent from a node's AcceptedCommandList, or refused by its
// access control.
package command

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/cybergarage/go-matter/matter/datamodel"
	"github.com/cybergarage/go-matter/matter/protocol/im"
)

var (
	// ErrUnknownCommand is returned when the catalog has no request command
	// with the cluster and command ID.
	ErrUnknownCommand = errors.New("unknown command")
	// ErrUnknownField is returned for a value whose name is not a field of
	// the command.
	ErrUnknownField = errors.New("unknown field")
	// ErrMissingField is returned when a mandatory field has no value.
	ErrMissingField = errors.New("missing field")
	// ErrInvalidValue is returned for a value a field does not accept.
	ErrInvalidValue = errors.New("invalid value")
	// ErrUnsupportedField is returned for a value of a field whose type
	// this package cannot encode, such as a list or a structure.
	ErrUnsupportedField = errors.New("unsupported field type")
	// ErrInvalidSchema is returned when the definition of a command in the
	// catalog cannot be interpreted.
	ErrInvalidSchema = errors.New("invalid command definition")
)

// Kind is the way the value of a field is encoded.
type Kind int

const (
	// KindUnsupported is a field this package cannot encode.
	KindUnsupported Kind = iota
	// KindBool is a boolean.
	KindBool
	// KindUnsigned is an unsigned integer.
	KindUnsigned
	// KindSigned is a signed integer.
	KindSigned
	// KindEnum is an unsigned integer which takes one of the Choices.
	KindEnum
	// KindBitmap is an unsigned integer made of the bits of the Choices.
	KindBitmap
	// KindString is a UTF-8 string.
	KindString
	// KindOctets is an octet string.
	KindOctets
)

// String returns the name of the kind.
func (k Kind) String() string {
	switch k {
	case KindBool:
		return "bool"
	case KindUnsigned:
		return "unsigned"
	case KindSigned:
		return "signed"
	case KindEnum:
		return "enum"
	case KindBitmap:
		return "bitmap"
	case KindString:
		return "string"
	case KindOctets:
		return "octets"
	case KindUnsupported:
		return "unsupported"
	default:
		return "unknown"
	}
}

// Choice is a named value of an enumeration, or a named mask of a bitmap.
type Choice struct {
	Name  string
	Value uint64
}

// Field describes one field of a command request.
type Field struct {
	// ID is the context tag of the field in the CommandFields structure.
	ID uint8
	// Name is the name of the field in the SDK definition.
	Name string
	// Type is the name of the type in the SDK definition.
	Type string
	// Kind is how a value is encoded.
	Kind Kind
	// Bits is the width of an integer, enumeration or bitmap.
	Bits int
	// Nullable reports whether the field accepts null.
	Nullable bool
	// Optional reports whether the field may be left out.
	Optional bool
	// Min and Max bound a KindSigned value.
	Min, Max int64
	// UMin and UMax bound a KindUnsigned value.
	UMin, UMax uint64
	// MinLength and MaxLength bound the length in bytes of a KindString
	// or KindOctets value; MaxLength is -1 when the definition sets none.
	MinLength, MaxLength int
	// Choices are the values of a KindEnum, or the masks of a KindBitmap.
	Choices []Choice
	// Unsupported says why the field is of KindUnsupported.
	Unsupported string
}

// Schema describes a command request and its fields, in the order of
// their IDs.
type Schema struct {
	ClusterID   im.ClusterID
	ClusterName string
	CommandID   im.CommandID
	CommandName string
	// Timed reports whether the command has to be sent as a timed invoke.
	// 8.7.2. Timed Interaction.
	Timed  bool
	Fields []Field
}

const (
	trueText        = "true"
	nullText        = "null"
	requestSource   = "client"
	argElement      = "arg"
	itemElement     = "item"
	fieldElement    = "field"
	atomicKind      = "atomic"
	enumKind        = "enum"
	bitmapKind      = "bitmap"
	booleanType     = "boolean"
	maxFieldID      = 0xFF
	noMaximumLength = -1
)

// New returns the schema of the request command of a cluster.
func New(catalog *datamodel.Catalog, clusterID im.ClusterID, commandID im.CommandID) (*Schema, error) {
	cluster, ok := catalog.Cluster(clusterID)
	if !ok {
		return nil, fmt.Errorf("%w: cluster 0x%04X is not in the catalog", ErrUnknownCommand, uint32(clusterID))
	}
	cmd, ok := cluster.Command(commandID, requestSource)
	if !ok {
		return nil, fmt.Errorf("%w: %s (0x%04X) has no request command 0x%02X in the catalog", ErrUnknownCommand, cluster.Name, uint32(clusterID), uint32(commandID))
	}
	s := &Schema{
		ClusterID:   clusterID,
		ClusterName: cluster.Name,
		CommandID:   commandID,
		CommandName: cmd.Name,
		Timed:       cmd.Timed,
	}
	seen := map[uint8]bool{}
	for index, arg := range cmd.Definition.NamedChildren(argElement) {
		f, err := newField(catalog, clusterID, arg, index)
		if err != nil {
			return nil, fmt.Errorf("%w: %s %s: %w", ErrInvalidSchema, cluster.Name, cmd.Name, err)
		}
		if seen[f.ID] {
			return nil, fmt.Errorf("%w: %s %s: duplicate field ID %d", ErrInvalidSchema, cluster.Name, cmd.Name, f.ID)
		}
		seen[f.ID] = true
		s.Fields = append(s.Fields, f)
	}
	sort.SliceStable(s.Fields, func(i, j int) bool { return s.Fields[i].ID < s.Fields[j].ID })
	return s, nil
}

// Field returns the field with the name, ignoring case.
func (s *Schema) Field(name string) (Field, bool) {
	for _, f := range s.Fields {
		if strings.EqualFold(f.Name, name) {
			return f, true
		}
	}
	return Field{}, false
}

func parseUnsigned(s string, bits int) (uint64, error) {
	s = strings.TrimSpace(s)
	base := 10
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		base = 16
		s = s[2:]
	}
	return strconv.ParseUint(s, base, bits)
}

func parseSigned(s string, bits int) (int64, error) {
	s = strings.TrimSpace(s)
	sign := ""
	if strings.HasPrefix(s, "-") {
		sign = "-"
		s = s[1:]
	}
	base := 10
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		base = 16
		s = s[2:]
	}
	return strconv.ParseInt(sign+s, base, bits)
}

func boolProperty(e datamodel.Element, name string) (bool, error) {
	switch e.Property(name) {
	case "", "false":
		return false, nil
	case trueText:
		return true, nil
	default:
		return false, fmt.Errorf("unsupported %s value", name)
	}
}

// fieldID returns the context tag of a command field. The SDK files write it
// as fieldId or as id; a file which writes neither numbers the fields by
// their position.
func fieldID(arg datamodel.Element, index int) (uint8, error) {
	text := arg.Property("fieldId")
	if text == "" {
		text = arg.Property("id")
	}
	if text == "" {
		if index > maxFieldID {
			return 0, errors.New("too many fields")
		}
		return uint8(index), nil
	}
	id, err := parseUnsigned(text, 8)
	if err != nil {
		return 0, fmt.Errorf("field ID %q", text)
	}
	return uint8(id), nil
}

func unsignedMax(bits int) uint64 {
	if bits >= 64 {
		return math.MaxUint64
	}
	return (uint64(1) << bits) - 1
}

func newField(catalog *datamodel.Catalog, clusterID im.ClusterID, arg datamodel.Element, index int) (Field, error) {
	f := Field{Name: arg.Property("name"), Type: arg.Property("type"), MaxLength: noMaximumLength}
	if f.Name == "" || f.Type == "" {
		return f, errors.New("field name or type missing")
	}
	var err error
	if f.ID, err = fieldID(arg, index); err != nil {
		return f, fmt.Errorf("%s: %w", f.Name, err)
	}
	if f.Nullable, err = boolProperty(arg, "isNullable"); err != nil {
		return f, fmt.Errorf("%s: %w", f.Name, err)
	}
	if f.Optional, err = boolProperty(arg, "optional"); err != nil {
		return f, fmt.Errorf("%s: %w", f.Name, err)
	}
	array, err := boolProperty(arg, "array")
	if err != nil {
		return f, fmt.Errorf("%s: %w", f.Name, err)
	}
	if array {
		f.Unsupported = "list fields are not supported"
		return f, nil
	}
	typ, ok := catalog.Type(f.Type, clusterID)
	if !ok {
		f.Unsupported = "the type " + f.Type + " is not in the catalog"
		return f, nil
	}
	switch typ.Kind {
	case atomicKind:
		if err := setAtomic(&f, typ.Definition); err != nil {
			return f, fmt.Errorf("%s: %w", f.Name, err)
		}
	case enumKind, bitmapKind:
		if err := setChoices(&f, catalog, clusterID, typ); err != nil {
			return f, fmt.Errorf("%s: %w", f.Name, err)
		}
	default:
		f.Unsupported = typ.Kind + " fields are not supported"
		return f, nil
	}
	if err := setBounds(&f, arg); err != nil {
		return f, fmt.Errorf("%s: %w", f.Name, err)
	}
	return f, nil
}

// setAtomic classifies an SDK atomic type. The SDK gives a size to every
// integer type, marks the signed ones, and marks strings as composite.
func setAtomic(f *Field, def datamodel.Element) error {
	name := def.Property("name")
	switch name {
	case booleanType:
		f.Kind = KindBool
		return nil
	case "char_string", "long_char_string":
		f.Kind = KindString
		return nil
	case "octet_string", "long_octet_string":
		f.Kind = KindOctets
		return nil
	case "single", "double":
		f.Unsupported = "floating point fields are not supported"
		return nil
	}
	if def.Property("composite") == trueText {
		f.Unsupported = name + " fields are not supported"
		return nil
	}
	size, err := strconv.Atoi(def.Property("size"))
	if err != nil || size < 1 || size > 8 {
		f.Unsupported = name + " fields are not supported"
		return nil //nolint:nilerr
	}
	f.Bits = size * 8
	if def.Property("signed") == trueText {
		f.Kind = KindSigned
		f.Min, f.Max = math.MinInt64, math.MaxInt64
		if f.Bits < 64 {
			f.Min = -(int64(1) << (f.Bits - 1))
			f.Max = (int64(1) << (f.Bits - 1)) - 1
		}
		return nil
	}
	f.Kind = KindUnsigned
	f.UMax = unsignedMax(f.Bits)
	return nil
}

func setChoices(f *Field, catalog *datamodel.Catalog, clusterID im.ClusterID, typ datamodel.TypeDefinition) error {
	base, ok := catalog.Type(typ.Definition.Property("type"), clusterID)
	if !ok || base.Kind != atomicKind {
		return fmt.Errorf("unknown base type of %s", typ.Name)
	}
	size, err := strconv.Atoi(base.Definition.Property("size"))
	if err != nil || size < 1 || size > 8 {
		return fmt.Errorf("unknown width of %s", typ.Name)
	}
	f.Bits = size * 8
	f.UMax = unsignedMax(f.Bits)
	element, property := itemElement, "value"
	f.Kind = KindEnum
	if typ.Kind == bitmapKind {
		element, property = fieldElement, "mask"
		f.Kind = KindBitmap
	}
	for _, child := range typ.Definition.NamedChildren(element) {
		v, err := parseUnsigned(child.Property(property), f.Bits)
		if err != nil {
			return fmt.Errorf("unresolved entry %s of %s", child.Property("name"), typ.Name)
		}
		f.Choices = append(f.Choices, Choice{Name: child.Property("name"), Value: v})
	}
	if f.Kind == KindEnum && len(f.Choices) == 0 {
		return fmt.Errorf("%s has no values", typ.Name)
	}
	return nil
}

// setBounds applies the min, max, minLength and length properties of a field.
// The bounds of an enumeration or a bitmap come from its entries instead.
func setBounds(f *Field, arg datamodel.Element) error {
	switch f.Kind {
	case KindSigned:
		if v := arg.Property("min"); v != "" {
			n, err := parseSigned(v, 64)
			if err != nil || n < f.Min {
				return errors.New("unresolved minimum")
			}
			f.Min = n
		}
		if v := arg.Property("max"); v != "" {
			n, err := parseSigned(v, 64)
			if err != nil || n > f.Max {
				return errors.New("unresolved maximum")
			}
			f.Max = n
		}
		if f.Min > f.Max {
			return errors.New("empty range")
		}
	case KindUnsigned:
		if v := arg.Property("min"); v != "" {
			n, err := parseUnsigned(v, 64)
			if err != nil {
				return errors.New("unresolved minimum")
			}
			f.UMin = n
		}
		if v := arg.Property("max"); v != "" {
			n, err := parseUnsigned(v, 64)
			if err != nil || n > f.UMax {
				return errors.New("unresolved maximum")
			}
			f.UMax = n
		}
		if f.UMin > f.UMax {
			return errors.New("empty range")
		}
	case KindString, KindOctets:
		if v := arg.Property("minLength"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 {
				return errors.New("unresolved minimum length")
			}
			f.MinLength = n
		}
		if v := arg.Property("length"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < f.MinLength {
				return errors.New("unresolved maximum length")
			}
			f.MaxLength = n
		}
	case KindUnsupported, KindBool, KindEnum, KindBitmap:
	}
	return nil
}
