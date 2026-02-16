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

package protocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

type payload struct {
	data []byte
}

// NewPayloadWithBytes creates a new Payload with the given data.
func NewPayloadWithBytes(data []byte) Payload {
	return &payload{data: data}
}

// NewPayloadFromReader reads the entire payload from the given reader and returns it as a Payload.
func NewPayloadFromReader(reader io.Reader) (Payload, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read payload data: %w", err)
	}
	return NewPayloadWithBytes(data), nil
}

// NewPayloadFromPrefixedReader reads a length-prefixed payload from the given reader and returns it as a Payload.
func NewPayloadFromPrefixedReader(reader io.Reader) (Payload, error) {
	var length uint16
	if err := binary.Read(reader, binary.LittleEndian, &length); err != nil {
		return nil, fmt.Errorf("failed to read payload length: %w", err)
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(reader, data); err != nil {
		return nil, fmt.Errorf("failed to read payload data: %w", err)
	}
	return NewPayloadWithBytes(data), nil
}

// NewPayloadFromPrefixedBytes reads a length-prefixed payload from the given byte slice and returns it as a Payload.
func NewPayloadFromPrefixedBytes(data []byte) (Payload, error) {
	return NewPayloadFromPrefixedReader(bytes.NewReader(data))
}

// Bytes returns the byte representation of the payload.
func (p *payload) Bytes() []byte {
	return p.data
}
