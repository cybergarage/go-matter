// Copyright (C) 2026 The go-matter Authors. All rights reserved.
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
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
)

type frame struct {
	header  Header
	payload []byte
}

// NewFrameFromReader parses a complete Matter frame from an io.Reader.
func NewFrameFromReader(reader io.Reader) (Frame, error) {
	header, err := NewHeaderFromReader(reader)
	if err != nil {
		return nil, err
	}

	payload, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read payload: %w", err)
	}

	return &frame{
		header:  header,
		payload: payload,
	}, nil
}

// NewFrameFromBytes parses a complete Matter frame from bytes.
func NewFrameFromBytes(data []byte) (Frame, error) {
	return NewFrameFromReader(bytes.NewReader(data))
}

// Header returns the header of the frame.
func (f *frame) Header() Header {
	return f.header
}

// Payload returns the payload of the frame.
func (f *frame) Payload() []byte {
	return f.payload
}

// Bytes returns the complete byte representation of the frame, including header and payload.
func (f *frame) Bytes() []byte {
	headerBytes := f.header.Bytes()
	result := make([]byte, 0, len(headerBytes)+len(f.payload))
	result = append(result, headerBytes...)
	result = append(result, f.payload...)
	return result
}

// String returns a human-readable representation of the frame for debugging purposes.
func (f *frame) String() string {
	return fmt.Sprintf("Frame{\n  %s\n  Payload: %d bytes [%s]\n}",
		f.header.String(),
		len(f.payload),
		hex.EncodeToString(f.payload))
}
