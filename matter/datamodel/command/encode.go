// Copyright (C) 2026 The go-matter Authors. Licensed under the Apache License, Version 2.0.

package command

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"unicode/utf8"

	"github.com/cybergarage/go-matter/matter/encoding/tlv"
)

// commandFieldsTag is the context tag of CommandFields in the CommandDataIB
// of an invoke request. 10.7.9. InvokeRequestMessage.
const commandFieldsTag = 1

// value is a validated value of a field, ready to be encoded.
type value struct {
	null     bool
	boolean  bool
	unsigned uint64
	signed   int64
	text     string
	octets   []byte
}

// Encode validates the values, keyed by field name, and returns the
// CommandFields structure to pass to an invoke. 10.7.9. InvokeRequestMessage.
//
// A value is given in its Go type or as text:
//
//   - nil, or the text "null" for a field which is not a string: null
//   - KindBool: a bool, or "true", "false", "1", "0"
//   - KindUnsigned, KindSigned: an integer, an integral float64 or
//     json.Number, or decimal or 0x-prefixed text
//   - KindEnum: the number or the name of one of the Choices
//   - KindBitmap: a number, or names of Choices joined with "|" or ","
//   - KindString: a string
//   - KindOctets: a []byte, or hexadecimal text
//
// Every mandatory field needs a value. An optional field without a value is
// left out. Field names are matched ignoring case.
func (s *Schema) Encode(values map[string]any) ([]byte, error) {
	given := map[uint8]any{}
	for name, v := range values {
		f, ok := s.Field(name)
		if !ok {
			return nil, fmt.Errorf("%w: %s has no field %q", ErrUnknownField, s.CommandName, name)
		}
		if _, dup := given[f.ID]; dup {
			return nil, fmt.Errorf("%w: %s given more than once", ErrInvalidValue, f.Name)
		}
		given[f.ID] = v
	}

	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewContextTag(commandFieldsTag))
	for _, f := range s.Fields {
		raw, ok := given[f.ID]
		if !ok {
			if f.Optional {
				continue
			}
			return nil, fmt.Errorf("%w: %s needs %s", ErrMissingField, s.CommandName, f.Name)
		}
		v, err := f.validate(raw)
		if err != nil {
			return nil, err
		}
		if err := f.put(enc, v); err != nil {
			return nil, fmt.Errorf("%s: %w", f.Name, err)
		}
	}
	if err := enc.EndContainer(); err != nil {
		return nil, err
	}
	return enc.Bytes(), nil
}

func (f Field) invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s: %s", ErrInvalidValue, f.Name, fmt.Sprintf(format, args...))
}

func (f Field) validate(raw any) (value, error) {
	if f.Kind == KindUnsupported {
		return value{}, fmt.Errorf("%w: %s (%s): %s", ErrUnsupportedField, f.Name, f.Type, f.Unsupported)
	}
	text, isText := raw.(string)
	if raw == nil || (isText && f.Kind != KindString && strings.EqualFold(strings.TrimSpace(text), nullText)) {
		if !f.Nullable {
			return value{}, f.invalid("null is not accepted")
		}
		return value{null: true}, nil
	}
	switch f.Kind {
	case KindBool:
		return f.validateBool(raw)
	case KindUnsigned:
		n, err := f.unsigned(raw)
		if err != nil {
			return value{}, err
		}
		if n < f.UMin || n > f.UMax {
			return value{}, f.invalid("%d is outside %d..%d", n, f.UMin, f.UMax)
		}
		return value{unsigned: n}, nil
	case KindSigned:
		n, err := f.signed(raw)
		if err != nil {
			return value{}, err
		}
		if n < f.Min || n > f.Max {
			return value{}, f.invalid("%d is outside %d..%d", n, f.Min, f.Max)
		}
		return value{signed: n}, nil
	case KindEnum:
		return f.validateEnum(raw)
	case KindBitmap:
		return f.validateBitmap(raw)
	case KindString:
		if !isText {
			return value{}, f.invalid("a string is expected")
		}
		if !utf8.ValidString(text) {
			return value{}, f.invalid("the string is not UTF-8")
		}
		if err := f.checkLength(len(text)); err != nil {
			return value{}, err
		}
		return value{text: text}, nil
	case KindOctets:
		return f.validateOctets(raw)
	case KindUnsupported:
	}
	return value{}, f.invalid("unsupported kind")
}

func (f Field) checkLength(n int) error {
	if n < f.MinLength || (f.MaxLength >= 0 && n > f.MaxLength) {
		if f.MaxLength < 0 {
			return f.invalid("length %d is shorter than %d", n, f.MinLength)
		}
		return f.invalid("length %d is outside %d..%d", n, f.MinLength, f.MaxLength)
	}
	return nil
}

func (f Field) validateBool(raw any) (value, error) {
	switch v := raw.(type) {
	case bool:
		return value{boolean: v}, nil
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case trueText, "1":
			return value{boolean: true}, nil
		case "false", "0":
			return value{boolean: false}, nil
		}
	}
	return value{}, f.invalid("true or false is expected")
}

// unsigned converts a number or numeric text to an unsigned integer.
func (f Field) unsigned(raw any) (uint64, error) {
	switch v := raw.(type) {
	case string:
		n, err := parseUnsigned(v, 64)
		if err != nil {
			return 0, f.invalid("%q is not an unsigned integer", v)
		}
		return n, nil
	case json.Number:
		return f.unsigned(v.String())
	case uint:
		return uint64(v), nil
	case uint8:
		return uint64(v), nil
	case uint16:
		return uint64(v), nil
	case uint32:
		return uint64(v), nil
	case uint64:
		return v, nil
	case float32:
		return f.unsigned(float64(v))
	case float64:
		if v < 0 || v != math.Trunc(v) || v >= 1<<63 {
			return 0, f.invalid("%v is not an unsigned integer", v)
		}
		return uint64(v), nil
	}
	n, err := f.signed(raw)
	if err != nil || n < 0 {
		return 0, f.invalid("an unsigned integer is expected")
	}
	return uint64(n), nil
}

// signed converts a number or numeric text to a signed integer.
func (f Field) signed(raw any) (int64, error) {
	switch v := raw.(type) {
	case string:
		n, err := parseSigned(v, 64)
		if err != nil {
			return 0, f.invalid("%q is not an integer", v)
		}
		return n, nil
	case json.Number:
		return f.signed(v.String())
	case int:
		return int64(v), nil
	case int8:
		return int64(v), nil
	case int16:
		return int64(v), nil
	case int32:
		return int64(v), nil
	case int64:
		return v, nil
	case uint, uint8, uint16, uint32, uint64:
		n, err := f.unsigned(v)
		if err != nil || n > math.MaxInt64 {
			return 0, f.invalid("%v is not an integer in range", v)
		}
		return int64(n), nil
	case float32:
		return f.signed(float64(v))
	case float64:
		if v != math.Trunc(v) || v >= 1<<63 || v < -(1<<63) {
			return 0, f.invalid("%v is not an integer", v)
		}
		return int64(v), nil
	}
	return 0, f.invalid("an integer is expected")
}

func (f Field) choiceNames() string {
	names := make([]string, 0, len(f.Choices))
	for _, c := range f.Choices {
		names = append(names, c.Name)
	}
	return strings.Join(names, ", ")
}

func (f Field) choice(name string) (Choice, bool) {
	for _, c := range f.Choices {
		if strings.EqualFold(c.Name, name) {
			return c, true
		}
	}
	return Choice{}, false
}

func (f Field) validateEnum(raw any) (value, error) {
	if text, ok := raw.(string); ok {
		if c, found := f.choice(strings.TrimSpace(text)); found {
			return value{unsigned: c.Value}, nil
		}
	}
	n, err := f.unsigned(raw)
	if err != nil {
		return value{}, f.invalid("one of %s is expected", f.choiceNames())
	}
	for _, c := range f.Choices {
		if c.Value == n {
			return value{unsigned: n}, nil
		}
	}
	return value{}, f.invalid("%d is not one of %s", n, f.choiceNames())
}

func (f Field) validateBitmap(raw any) (value, error) {
	var all uint64
	for _, c := range f.Choices {
		all |= c.Value
	}
	n, err := f.unsigned(raw)
	if err != nil {
		text, ok := raw.(string)
		if !ok {
			return value{}, err
		}
		n = 0
		for _, name := range strings.FieldsFunc(text, func(r rune) bool { return r == '|' || r == ',' }) {
			c, found := f.choice(strings.TrimSpace(name))
			if !found {
				return value{}, f.invalid("%q is not one of %s", strings.TrimSpace(name), f.choiceNames())
			}
			n |= c.Value
		}
	}
	if n&^all != 0 {
		return value{}, f.invalid("0x%X sets bits outside %s", n, f.choiceNames())
	}
	return value{unsigned: n}, nil
}

func (f Field) validateOctets(raw any) (value, error) {
	var octets []byte
	switch v := raw.(type) {
	case []byte:
		octets = v
	case string:
		text := strings.TrimSpace(v)
		if strings.HasPrefix(strings.ToLower(text), "0x") {
			text = text[2:]
		}
		b, err := hex.DecodeString(text)
		if err != nil {
			return value{}, f.invalid("hexadecimal text is expected")
		}
		octets = b
	default:
		return value{}, f.invalid("bytes or hexadecimal text are expected")
	}
	if err := f.checkLength(len(octets)); err != nil {
		return value{}, err
	}
	return value{octets: octets}, nil
}

func (f Field) put(enc tlv.Encoder, v value) error {
	tag := tlv.NewContextTag(f.ID)
	if v.null {
		enc.PutNull(tag)
		return nil
	}
	switch f.Kind {
	case KindBool:
		enc.PutBool(tag, v.boolean)
	case KindUnsigned, KindEnum, KindBitmap:
		return enc.PutUnsigned(tag, v.unsigned)
	case KindSigned:
		return enc.PutSigned(tag, v.signed)
	case KindString:
		return enc.PutUTF8(tag, v.text)
	case KindOctets:
		return enc.PutOctet(tag, v.octets)
	case KindUnsupported:
		return ErrUnsupportedField
	}
	return nil
}
