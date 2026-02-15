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

// Encoder defines the interface for producing TLV-encoded data using the
// control octet format (TagControl in bits 7..5, ElementType in bits 4..0).
type Encoder interface {
	// PutSigned encodes a signed integer using the minimal fitting size (1/2/4/8).
	PutSigned(tag Tag, v int64) error
	// PutUnsigned encodes an unsigned integer using the minimal fitting size (1/2/4/8).
	PutUnsigned(tag Tag, v uint64) error
	// PutBool encodes a boolean (selects ETBoolFalse or ETBoolTrue).
	PutBool(tag Tag, v bool)
	// PutNull encodes a null element (no payload).
	PutNull(tag Tag)
	// PutFloat32 encodes a 32-bit floating point value (ETFloat32).
	PutFloat32(tag Tag, f float32)
	// PutFloat64 encodes a 64-bit floating point value (ETFloat64).
	PutFloat64(tag Tag, f float64)
	// PutUTF8 encodes a UTF-8 string with an adaptive length-of-length field.
	PutUTF8(tag Tag, s string) error
	// PutBytes encodes a raw byte slice with an adaptive length-of-length field.
	PutBytes(tag Tag, b []byte) error

	// StartStructure emits the Structure container start.
	StartStructure(tag Tag)
	// StartArray emits the Array container start.
	StartArray(tag Tag)
	// StartList emits the List container start.
	StartList(tag Tag)
	// EndContainer emits an EndOfContainer marker for the most recent container.
	EndContainer() error
	// MustEndAll closes all open containers (ignoring errors).
	MustEndAll()

	// Bytes returns the accumulated encoded bytes. The returned slice must not be mutated.
	Bytes() []byte
}

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
	if tb := tag.SerializeTag(); len(tb) > 0 {
		e.buf.Write(tb)
	}
}

// PutSigned implements Encoder.PutSigned.
func (e *encoderImpl) PutSigned(tag Tag, v int64) error {
	var et ElementType
	switch {
	case v >= math.MinInt8 && v <= math.MaxInt8:
		et = ETSignedInt1
	case v >= math.MinInt16 && v <= math.MaxInt16:
		et = ETSignedInt2
	case v >= math.MinInt32 && v <= math.MaxInt32:
		et = ETSignedInt4
	default:
		et = ETSignedInt8
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

// PutUnsigned implements Encoder.PutUnsigned.
func (e *encoderImpl) PutUnsigned(tag Tag, v uint64) error {
	var et ElementType
	switch {
	case v <= math.MaxUint8:
		et = ETUnsignedInt1
	case v <= math.MaxUint16:
		et = ETUnsignedInt2
	case v <= math.MaxUint32:
		et = ETUnsignedInt4
	default:
		et = ETUnsignedInt8
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

// PutBool implements Encoder.PutBool.
func (e *encoderImpl) PutBool(tag Tag, v bool) {
	if v {
		e.writeHeader(tag, ETBoolTrue)
	} else {
		e.writeHeader(tag, ETBoolFalse)
	}
}

// PutNull implements Encoder.PutNull.
func (e *encoderImpl) PutNull(tag Tag) {
	e.writeHeader(tag, ETNull)
}

// PutFloat32 implements Encoder.PutFloat32.
func (e *encoderImpl) PutFloat32(tag Tag, f float32) {
	e.writeHeader(tag, ETFloat32)
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, math.Float32bits(f))
	e.buf.Write(buf)
}

// PutFloat64 implements Encoder.PutFloat64.
func (e *encoderImpl) PutFloat64(tag Tag, f float64) {
	e.writeHeader(tag, ETFloat64)
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

// PutBytes implements Encoder.PutBytes.
func (e *encoderImpl) PutBytes(tag Tag, b []byte) error {
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

// pickStringElementType chooses the appropriate string/bytes ElementType based
// on payload length and whether it's UTF-8. Returns chosen type, length-of-length,
// and error (always nil here).
func pickStringElementType(length int, utf8 bool) (ElementType, int, error) {
	switch {
	case length <= 0xFF:
		if utf8 {
			return ETUTF8String1, 1, nil
		}
		return ETOctetString1, 1, nil
	case length <= 0xFFFF:
		if utf8 {
			return ETUTF8String2, 2, nil
		}
		return ETOctetString2, 2, nil
	case length <= 0xFFFFFFFF:
		if utf8 {
			return ETUTF8String4, 4, nil
		}
		return ETOctetString4, 4, nil
	default:
		if utf8 {
			return ETUTF8String8, 8, nil
		}
		return ETOctetString8, 8, nil
	}
}

// StartStructure implements Encoder.StartStructure.
func (e *encoderImpl) StartStructure(tag Tag) {
	e.writeHeader(tag, ETStructure)
	e.containers = append(e.containers, ETStructure)
}

// StartArray implements Encoder.StartArray.
func (e *encoderImpl) StartArray(tag Tag) {
	e.writeHeader(tag, ETArray)
	e.containers = append(e.containers, ETArray)
}

// StartList implements Encoder.StartList.
func (e *encoderImpl) StartList(tag Tag) {
	e.writeHeader(tag, ETList)
	e.containers = append(e.containers, ETList)
}

// EndContainer implements Encoder.EndContainer.
func (e *encoderImpl) EndContainer() error {
	if len(e.containers) == 0 {
		return ErrContainerStackEmpty
	}
	e.writeHeader(AnonymousTag(), ETEndOfContainer)
	e.containers = e.containers[:len(e.containers)-1]
	return nil
}

// MustEndAll implements Encoder.MustEndAll.
func (e *encoderImpl) MustEndAll() {
	for len(e.containers) > 0 {
		_ = e.EndContainer()
	}
}
