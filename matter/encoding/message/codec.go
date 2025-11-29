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

package message

import (
	"encoding/binary"
	"fmt"
	"slices"
)

// FrameEncoder defines an interface for encoding Frame objects into raw bytes.
type FrameEncoder interface {
	// Encode encodes the provided Frame into a newly allocated byte slice.
	Encode(f Message) ([]byte, error)
	// EncodeInto encodes the provided Frame into the supplied buffer, returning bytes written.
	EncodeInto(f Message, dst []byte) (int, error)
	// ComputeLength returns the number of bytes required to encode the Frame.
	ComputeLength(f Message) (int, error)
}

// FrameDecoder defines an interface for decoding raw bytes into Frame objects.
type FrameDecoder interface {
	// Decode parses the raw byte slice into a new Frame instance.
	Decode(src []byte) (Message, error)
	// PeekFrameControl extracts version, type, and presence flags without full decode.
	PeekFrameControl(src []byte) (version FrameVersion, frameType FrameType, hasSrc, hasDst bool, err error)
	// Validate verifies minimal structural correctness (length, supported version).
	Validate(src []byte) error
}

// BasicFrameCodec implements both FrameEncoder and FrameDecoder for the Frame interface.
type BasicFrameCodec struct {
	// AllowedVersions lists accepted versions; if empty, FrameVersion1 is assumed.
	AllowedVersions []FrameVersion
	// MinMICLength is the minimal allowable MIC length.
	MinMICLength int
	// MaxMICLength is the maximal allowable MIC length.
	MaxMICLength int
}

// NewBasicFrameCodec creates a new codec with default policies.
func NewBasicFrameCodec() *BasicFrameCodec {
	return &BasicFrameCodec{
		AllowedVersions: []FrameVersion{FrameVersion1},
		MinMICLength:    0,
		MaxMICLength:    32,
	}
}

// Encode allocates a buffer and encodes the frame into it.
func (c *BasicFrameCodec) Encode(f Message) ([]byte, error) {
	total, err := c.ComputeLength(f)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, total)
	_, err = c.EncodeInto(f, buf)
	return buf, err
}

// EncodeInto encodes the frame into an existing buffer.
func (c *BasicFrameCodec) EncodeInto(f Message, dst []byte) (int, error) {
	if f.Payload() == nil {
		return 0, ErrPayloadMissing
	}
	if err := c.validateVersion(f.Version()); err != nil {
		return 0, err
	}
	total, err := c.ComputeLength(f)
	if err != nil {
		return 0, err
	}
	if len(dst) < total {
		return 0, ErrBufferTooSmall
	}

	// Build frame control (example bit layout).
	var frameControl uint16
	frameControl |= uint16(f.Version() & 0x03) // bits 0-1
	if f.HasSourceNodeID() {
		frameControl |= 1 << 2
	} // bit 2
	if f.HasDestNodeID() {
		frameControl |= 1 << 3
	} // bit 3
	frameControl |= uint16((f.Type() & 0x0F) << 4) // bits 4-7
	// bits 8-15 reserved

	offset := 0
	write := func(b []byte) {
		copy(dst[offset:], b)
		offset += len(b)
	}

	tmp2 := make([]byte, 2)
	binary.LittleEndian.PutUint16(tmp2, frameControl)
	write(tmp2)

	binary.LittleEndian.PutUint16(tmp2, f.SessionID())
	write(tmp2)

	dst[offset] = f.SecurityFlags()
	offset++

	tmp4 := make([]byte, 4)
	binary.LittleEndian.PutUint32(tmp4, f.MessageCounter())
	write(tmp4)

	if f.HasSourceNodeID() {
		tmp8 := make([]byte, 8)
		binary.LittleEndian.PutUint64(tmp8, f.SourceNodeID())
		write(tmp8)
	}
	if f.HasDestNodeID() {
		tmp8 := make([]byte, 8)
		binary.LittleEndian.PutUint64(tmp8, f.DestNodeID())
		write(tmp8)
	}

	write(f.Payload())

	if len(f.MIC()) > 0 {
		write(f.MIC())
	}

	return offset, nil
}

// ComputeLength returns the encoded length of the frame, validating MIC limits.
func (c *BasicFrameCodec) ComputeLength(f Message) (int, error) {
	if err := c.validateVersion(f.Version()); err != nil {
		return 0, err
	}
	micLen := len(f.MIC())
	if micLen < c.MinMICLength {
		return 0, fmt.Errorf("%w: got %d < %d", ErrMICLengthMismatch, micLen, c.MinMICLength)
	}
	if micLen > c.MaxMICLength {
		return 0, fmt.Errorf("%w: got %d > %d", ErrMICLengthMismatch, micLen, c.MaxMICLength)
	}
	if f.Payload() == nil {
		return 0, ErrPayloadMissing
	}

	length := 0
	length += 2 // frame control
	length += 2 // session id
	length += 1 // security flags
	length += 4 // message counter
	if f.HasSourceNodeID() {
		length += 8
	}
	if f.HasDestNodeID() {
		length += 8
	}
	length += len(f.Payload())
	length += micLen
	return length, nil
}

// Decode builds a new Frame from the raw buffer.
func (c *BasicFrameCodec) Decode(src []byte) (Message, error) {
	if len(src) < 2+2+1+4 {
		return nil, ErrInvalidFrameLength
	}
	version, frameType, hasSrc, hasDst, err := c.PeekFrameControl(src)
	if err != nil {
		return nil, err
	}
	if err := c.validateVersion(version); err != nil {
		return nil, err
	}

	// Create new frame (fluent style).
	f := newBasicFrameWith().
		SetVersion(version).
		SetType(frameType).
		SetSourceNodeIDPresent(hasSrc).
		SetDestNodeIDPresent(hasDst)

	offset := 0
	read16 := func() uint16 {
		v := binary.LittleEndian.Uint16(src[offset:])
		offset += 2
		return v
	}
	read8 := func() uint8 {
		v := src[offset]
		offset++
		return v
	}
	read32 := func() uint32 {
		v := binary.LittleEndian.Uint32(src[offset:])
		offset += 4
		return v
	}
	read64 := func() uint64 {
		v := binary.LittleEndian.Uint64(src[offset:])
		offset += 8
		return v
	}

	_ = read16() // frame control already parsed
	f.SetSessionID(read16()).
		SetSecurityFlags(read8()).
		SetMessageCounter(read32())

	if hasSrc {
		if len(src[offset:]) < 8 {
			return nil, ErrInvalidFrameLength
		}
		f.SetSourceNodeID(read64())
	}
	if hasDst {
		if len(src[offset:]) < 8 {
			return nil, ErrInvalidFrameLength
		}
		f.SetDestNodeID(read64())
	}

	// Remaining bytes are (payload + MIC) - simplified (no MIC split).
	rest := make([]byte, len(src[offset:]))
	copy(rest, src[offset:])
	f.SetPayload(rest)

	return f, nil
}

// PeekFrameControl extracts minimal frame metadata.
func (c *BasicFrameCodec) PeekFrameControl(src []byte) (FrameVersion, FrameType, bool, bool, error) {
	if len(src) < 2 {
		return 0, 0, false, false, ErrInvalidFrameLength
	}
	fc := binary.LittleEndian.Uint16(src[:2])
	version := FrameVersion(fc & 0x03)
	hasSrc := (fc & (1 << 2)) != 0
	hasDst := (fc & (1 << 3)) != 0
	frameType := FrameType((fc >> 4) & 0x0F)
	return version, frameType, hasSrc, hasDst, nil
}

// Validate performs basic structural checks.
func (c *BasicFrameCodec) Validate(src []byte) error {
	if len(src) < 2+2+1+4 {
		return ErrInvalidFrameLength
	}
	version, _, _, _, err := c.PeekFrameControl(src)
	if err != nil {
		return err
	}
	return c.validateVersion(version)
}

func (c *BasicFrameCodec) validateVersion(v FrameVersion) error {
	if len(c.AllowedVersions) == 0 {
		if v == FrameVersion1 {
			return nil
		}
		return ErrUnknownVersion
	}
	if slices.Contains(c.AllowedVersions, v) {
		return nil
	}
	return ErrUnknownVersion
}
