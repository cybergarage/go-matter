// Copyright (C) 2025 The go-matter Authors. All rights reserved.
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

package tlv

import (
	"encoding/binary"
)

// decoderImpl is the concrete implementation of Decoder.
type decoderImpl struct {
	data []byte
	pos  int
	err  error

	next       Element
	containerS []ElementType
}

var _ Decoder = (*decoderImpl)(nil)

// NewDecoderWithBytes constructs a new decoder over b.
func NewDecoderWithBytes(b []byte) Decoder {
	return &decoderImpl{
		data:       b,
		pos:        0,
		err:        nil,
		next:       nil,
		containerS: []ElementType{},
	}
}

func (d *decoderImpl) Error() error {
	return d.err
}

func (d *decoderImpl) More() bool {
	return d.err == nil && d.pos < len(d.data)
}

func (d *decoderImpl) Next() bool {
	if d.err != nil {
		return false
	}
	if d.pos >= len(d.data) {
		if len(d.containerS) != 0 {
			d.err = ErrUnexpectedEOF
		}
		return false
	}
	el, err := d.readElement()
	if err != nil {
		d.err = err
		return false
	}
	if containerElement(el.Type()) {
		switch el.Type() {
		case Structure, Array, List:
			d.containerS = append(d.containerS, el.Type())
		case EndOfContainer:
			if len(d.containerS) == 0 {
				d.err = ErrContainerStackEmpty
				return false
			}
			d.containerS = d.containerS[:len(d.containerS)-1]
			// Skip yielding end marker; continue to next
			return d.Next()
		}
	}
	d.next = el
	return true
}

func (d *decoderImpl) Element() Element {
	return d.next
}

func (d *decoderImpl) read(n int) ([]byte, error) {
	if d.pos+n > len(d.data) {
		return nil, ErrUnexpectedEOF
	}
	b := d.data[d.pos : d.pos+n]
	d.pos += n
	return b, nil
}

func (d *decoderImpl) readElement() (Element, error) {
	ctrlB, err := d.read(1)
	if err != nil {
		return nil, err
	}
	tc, et := decodeControl(ctrlB[0])

	tag, consumed, err := decodeTagBytes(tc, d.data[d.pos:])
	if err != nil {
		return nil, err
	}
	d.pos += consumed

	e := &elementImpl{
		tag:           tag,
		et:            et,
		signedValue:   nil,
		unsignedValue: nil,
		boolValue:     nil,
		floatValue:    nil,
		strValue:      nil,
		bytesValue:    nil,
	}

	switch et {
	case SignedInt1, SignedInt2, SignedInt4, SignedInt8:
		sBytes := numericSigned(et)
		raw, err := d.read(sBytes)
		if err != nil {
			return nil, err
		}
		val := decodeSigned(raw)
		e.signedValue = &val
		return e, nil
	case UnsignedInt1, UnsignedInt2, UnsignedInt4, UnsignedInt8:
		uBytes := numericUnsigned(et)
		raw, err := d.read(uBytes)
		if err != nil {
			return nil, err
		}
		val := decodeUnsigned(raw)
		e.unsignedValue = &val
		return e, nil
	case BoolTrue:
		v := true
		e.boolValue = &v
		return e, nil
	case BoolFalse:
		v := false
		e.boolValue = &v
		return e, nil
	case Float32, Float64:
		fs := floatSize(et)
		raw, err := d.read(fs)
		if err != nil {
			return nil, err
		}
		fv := decodeFloat(raw)
		e.floatValue = &fv
		return e, nil
	case UTF8String1, UTF8String2, UTF8String4, UTF8String8,
		OctetString1, OctetString2, OctetString4, OctetString8:
		lfs, isUTF8 := stringLenFieldSize(et)
		lenBytes, err := d.read(lfs)
		if err != nil {
			return nil, err
		}
		var length uint64
		switch lfs {
		case 1:
			length = uint64(lenBytes[0])
		case 2:
			length = uint64(binary.LittleEndian.Uint16(lenBytes))
		case 4:
			length = uint64(binary.LittleEndian.Uint32(lenBytes))
		case 8:
			length = binary.LittleEndian.Uint64(lenBytes)
		}
		if length > uint64(len(d.data)-d.pos) {
			return nil, ErrUnexpectedEOF
		}
		raw, err := d.read(int(length))
		if err != nil {
			return nil, err
		}
		if isUTF8 {
			s := string(raw)
			e.strValue = &s
		} else {
			cp := make([]byte, len(raw))
			copy(cp, raw)
			e.bytesValue = &cp
		}
		return e, nil
	case Null:
		return e, nil
	case Structure, Array, List, EndOfContainer:
		return e, nil
	default:
		return nil, ErrUnknownElementType
	}
}
