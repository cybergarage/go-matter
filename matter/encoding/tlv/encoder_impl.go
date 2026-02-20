// Copyright (C) 2024 The go-matter Authors. All rights reserved.
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
	"bytes"
	"encoding/binary"
	"math"
)

// encoderImpl is the concrete implementation of Encoder.
type encoderImpl struct {
	buf        bytes.Buffer
	containers []ElementType
}

var _ Encoder = (*encoderImpl)(nil)

// NewEncoder creates a new encoder implementation instance.
func NewEncoder() Encoder {
	return &encoderImpl{
		buf:        bytes.Buffer{},
		containers: []ElementType{},
	}
}

// Bytes returns the currently encoded TLV bytes (no copy).
func (e *encoderImpl) Bytes() []byte { return e.buf.Bytes() }

// writeHeader writes the control octet and tag bytes for the given element type.
func (e *encoderImpl) writeHeader(tag Tag, et ElementType) {
	ctrl := encodeControl(tag.Control(), et)
	e.buf.WriteByte(ctrl)
	if tb := tag.Bytes(); len(tb) > 0 {
		e.buf.Write(tb)
	}
}

// PutSigned implements Encoder.PutSigned.
func (e *encoderImpl) PutSigned(tag Tag, v int64) error {
	var et ElementType
	switch {
	case v >= math.MinInt8 && v <= math.MaxInt8:
		et = SignedInt1
	case v >= math.MinInt16 && v <= math.MaxInt16:
		et = SignedInt2
	case v >= math.MinInt32 && v <= math.MaxInt32:
		et = SignedInt4
	default:
		et = SignedInt8
	}
	e.writeHeader(tag, et)
	size := numericSigned(et)
	buf := make([]byte, size)
	switch size {
	case 1:
		buf[0] = byte(int8(v))
	case 2:
		binary.LittleEndian.PutUint16(buf, uint16(v))
	case 4:
		binary.LittleEndian.PutUint32(buf, uint32(v))
	case 8:
		binary.LittleEndian.PutUint64(buf, uint64(v))
	}
	e.buf.Write(buf)
	return nil
}

// PutSigned1 implements Encoder.PutSigned1.
func (e *encoderImpl) PutSigned1(tag Tag, v int8) {
	e.writeHeader(tag, SignedInt1)
	e.buf.WriteByte(byte(v))
}

// PutSigned2 implements Encoder.PutSigned2.
func (e *encoderImpl) PutSigned2(tag Tag, v int16) {
	e.writeHeader(tag, SignedInt2)
	buf := make([]byte, 2)
	binary.LittleEndian.PutUint16(buf, uint16(v))
	e.buf.Write(buf)
}

// PutSigned4 implements Encoder.PutSigned4.
func (e *encoderImpl) PutSigned4(tag Tag, v int32) {
	e.writeHeader(tag, SignedInt4)
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, uint32(v))
	e.buf.Write(buf)
}

// PutSigned8 implements Encoder.PutSigned8.
func (e *encoderImpl) PutSigned8(tag Tag, v int64) {
	e.writeHeader(tag, SignedInt8)
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, uint64(v))
	e.buf.Write(buf)
}

// PutUnsigned implements Encoder.PutUnsigned.
func (e *encoderImpl) PutUnsigned(tag Tag, v uint64) error {
	var et ElementType
	switch {
	case v <= math.MaxUint8:
		et = UnsignedInt1
	case v <= math.MaxUint16:
		et = UnsignedInt2
	case v <= math.MaxUint32:
		et = UnsignedInt4
	default:
		et = UnsignedInt8
	}
	e.writeHeader(tag, et)
	size := numericUnsigned(et)
	buf := make([]byte, size)
	switch size {
	case 1:
		buf[0] = byte(v)
	case 2:
		binary.LittleEndian.PutUint16(buf, uint16(v))
	case 4:
		binary.LittleEndian.PutUint32(buf, uint32(v))
	case 8:
		binary.LittleEndian.PutUint64(buf, v)
	}
	e.buf.Write(buf)
	return nil
}

// PutUnsigned1 implements Encoder.PutUnsigned1.
func (e *encoderImpl) PutUnsigned1(tag Tag, v uint8) {
	e.writeHeader(tag, UnsignedInt1)
	e.buf.WriteByte(byte(v))
}

// PutUnsigned2 implements Encoder.PutUnsigned2.
func (e *encoderImpl) PutUnsigned2(tag Tag, v uint16) {
	e.writeHeader(tag, UnsignedInt2)
	buf := make([]byte, 2)
	binary.LittleEndian.PutUint16(buf, v)
	e.buf.Write(buf)
}

// PutUnsigned4 implements Encoder.PutUnsigned4.
func (e *encoderImpl) PutUnsigned4(tag Tag, v uint32) {
	e.writeHeader(tag, UnsignedInt4)
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, v)
	e.buf.Write(buf)
}

// PutUnsigned8 implements Encoder.PutUnsigned8.
func (e *encoderImpl) PutUnsigned8(tag Tag, v uint64) {
	e.writeHeader(tag, UnsignedInt8)
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, v)
	e.buf.Write(buf)
}

// PutBool implements Encoder.PutBool.
func (e *encoderImpl) PutBool(tag Tag, v bool) {
	if v {
		e.writeHeader(tag, BoolTrue)
	} else {
		e.writeHeader(tag, BoolFalse)
	}
}

// PutNull implements Encoder.PutNull.
func (e *encoderImpl) PutNull(tag Tag) {
	e.writeHeader(tag, Null)
}

// PutFloat32 implements Encoder.PutFloat32.
func (e *encoderImpl) PutFloat32(tag Tag, f float32) {
	e.writeHeader(tag, Float32)
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, math.Float32bits(f))
	e.buf.Write(buf)
}

// PutFloat64 implements Encoder.PutFloat64.
func (e *encoderImpl) PutFloat64(tag Tag, f float64) {
	e.writeHeader(tag, Float64)
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, math.Float64bits(f))
	e.buf.Write(buf)
}

// PutUTF8 implements Encoder.PutUTF8.
func (e *encoderImpl) PutUTF8(tag Tag, s string) error {
	l := len(s)
	et, lenSize, err := pickStringElementType(l, true)
	if err != nil {
		return err
	}
	e.writeHeader(tag, et)
	lenBuf := make([]byte, lenSize)
	switch lenSize {
	case 1:
		lenBuf[0] = byte(l)
	case 2:
		binary.LittleEndian.PutUint16(lenBuf, uint16(l))
	case 4:
		binary.LittleEndian.PutUint32(lenBuf, uint32(l))
	case 8:
		binary.LittleEndian.PutUint64(lenBuf, uint64(l))
	}
	e.buf.Write(lenBuf)
	e.buf.WriteString(s)
	return nil
}

// PutUTF81 implements Encoder.PutUTF81.
func (e *encoderImpl) PutUTF81(tag Tag, s string) error {
	l := len(s)
	if l > 0xFF {
		return ErrStringTooLong
	}
	e.writeHeader(tag, UTF8String1)
	e.buf.WriteByte(byte(l))
	e.buf.WriteString(s)
	return nil
}

// PutUTF82 implements Encoder.PutUTF82.
func (e *encoderImpl) PutUTF82(tag Tag, s string) error {
	l := len(s)
	if l > 0xFFFF {
		return ErrStringTooLong
	}
	e.writeHeader(tag, UTF8String2)
	lenBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(lenBuf, uint16(l))
	e.buf.Write(lenBuf)
	e.buf.WriteString(s)
	return nil
}

// PutUTF84 implements Encoder.PutUTF84.
func (e *encoderImpl) PutUTF84(tag Tag, s string) error {
	l := len(s)
	if l > 0xFFFFFFFF {
		return ErrStringTooLong
	}
	e.writeHeader(tag, UTF8String4)
	lenBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBuf, uint32(l))
	e.buf.Write(lenBuf)
	e.buf.WriteString(s)
	return nil
}

// PutUTF88 implements Encoder.PutUTF88.
func (e *encoderImpl) PutUTF88(tag Tag, s string) error {
	l := len(s)
	e.writeHeader(tag, UTF8String8)
	lenBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(lenBuf, uint64(l))
	e.buf.Write(lenBuf)
	e.buf.WriteString(s)
	return nil
}

// PutOctet implements Encoder.PutOctet.
func (e *encoderImpl) PutOctet(tag Tag, b []byte) error {
	l := len(b)
	et, lenSize, err := pickStringElementType(l, false)
	if err != nil {
		return err
	}
	e.writeHeader(tag, et)
	lenBuf := make([]byte, lenSize)
	switch lenSize {
	case 1:
		lenBuf[0] = byte(l)
	case 2:
		binary.LittleEndian.PutUint16(lenBuf, uint16(l))
	case 4:
		binary.LittleEndian.PutUint32(lenBuf, uint32(l))
	case 8:
		binary.LittleEndian.PutUint64(lenBuf, uint64(l))
	}
	e.buf.Write(lenBuf)
	e.buf.Write(b)
	return nil
}

// PutOctet1 implements Encoder.PutOctet1.
func (e *encoderImpl) PutOctet1(tag Tag, b []byte) error {
	l := len(b)
	if l > 0xFF {
		return ErrOctetTooLong
	}
	e.writeHeader(tag, OctetString1)
	e.buf.WriteByte(byte(l))
	e.buf.Write(b)
	return nil
}

// PutOctet2 implements Encoder.PutOctet2.
func (e *encoderImpl) PutOctet2(tag Tag, b []byte) error {
	l := len(b)
	if l > 0xFFFF {
		return ErrOctetTooLong
	}
	e.writeHeader(tag, OctetString2)
	lenBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(lenBuf, uint16(l))
	e.buf.Write(lenBuf)
	e.buf.Write(b)
	return nil
}

// PutOctet4 implements Encoder.PutOctet4.
func (e *encoderImpl) PutOctet4(tag Tag, b []byte) error {
	l := len(b)
	if l > 0xFFFFFFFF {
		return ErrOctetTooLong
	}
	e.writeHeader(tag, OctetString4)
	lenBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBuf, uint32(l))
	e.buf.Write(lenBuf)
	e.buf.Write(b)
	return nil
}

// PutOctet8 implements Encoder.PutOctet8.
func (e *encoderImpl) PutOctet8(tag Tag, b []byte) error {
	l := len(b)
	e.writeHeader(tag, OctetString8)
	lenBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(lenBuf, uint64(l))
	e.buf.Write(lenBuf)
	e.buf.Write(b)
	return nil
}

// pickStringElementType chooses the appropriate string/bytes ElementType based
// on payload length and whether it's UTF-8. Returns chosen type, length-of-length,
// and error (always nil here).
func pickStringElementType(length int, utf8 bool) (ElementType, int, error) {
	switch {
	case length <= 0xFF:
		if utf8 {
			return UTF8String1, 1, nil
		}
		return OctetString1, 1, nil
	case length <= 0xFFFF:
		if utf8 {
			return UTF8String2, 2, nil
		}
		return OctetString2, 2, nil
	case length <= 0xFFFFFFFF:
		if utf8 {
			return UTF8String4, 4, nil
		}
		return OctetString4, 4, nil
	default:
		if utf8 {
			return UTF8String8, 8, nil
		}
		return OctetString8, 8, nil
	}
}

// BeginStructure implements Encoder.BeginStructure.
func (e *encoderImpl) BeginStructure(tag Tag) {
	e.writeHeader(tag, Structure)
	e.containers = append(e.containers, Structure)
}

// BeginArray implements Encoder.BeginArray.
func (e *encoderImpl) BeginArray(tag Tag) {
	e.writeHeader(tag, Array)
	e.containers = append(e.containers, Array)
}

// BeginList implements Encoder.BeginList.
func (e *encoderImpl) BeginList(tag Tag) {
	e.writeHeader(tag, List)
	e.containers = append(e.containers, List)
}

// EndContainer implements Encoder.EndContainer.
func (e *encoderImpl) EndContainer() error {
	if len(e.containers) == 0 {
		return ErrContainerStackEmpty
	}
	e.writeHeader(NewAnonymousTag(), EndOfContainer)
	e.containers = e.containers[:len(e.containers)-1]
	return nil
}

// MustEndAll implements Encoder.MustEndAll.
func (e *encoderImpl) MustEndAll() {
	for len(e.containers) > 0 {
		_ = e.EndContainer()
	}
}
