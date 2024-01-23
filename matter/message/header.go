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

package message

import (
	"io"

	"github.com/cybergarage/go-matter/matter/encoding"
)

// 4.4.1. Message Header Field Descriptions
// Header represents a message header.
type Header struct {
	length            [2]byte
	flag              Flag
	SessionId         SessionId
	SecurityFlag      SecurityFlag
	Counter           Counter
	SourceNodeId      NodeId
	DestinationNodeId NodeId
}

// NewHeader returns a new header.
func NewHeader() *Header {
	header := &Header{
		length:            [2]byte{},
		flag:              0,
		SessionId:         0,
		SecurityFlag:      0,
		Counter:           0,
		SourceNodeId:      0,
		DestinationNodeId: 0,
	}
	return header
}

// SetLength sets a length.
func (header *Header) SetLength(l uint16) {
	encoding.Uint16ToBytes(l, &header.length)
}

// Length returns a length.
func (header *Header) Length() uint16 {
	return encoding.Byte2ToUint16(header.length)
}

// SetFlag sets a flag.
func (header *Header) SetFlag(f Flag) {
	header.flag = f
}

// Flag returns a flag.
func (header *Header) Flag() Flag {
	return header.flag
}

// Read reads a header from the specified reader.
func (header *Header) Read(reader io.Reader) error {
	b := make([]byte, 1)
	// 4.4.1. Message Header Field Descriptions
	// Message Length
	_, err := reader.Read(header.length[:])
	if err != nil {
		return err
	}
	// Message Flags
	_, err = reader.Read(b)
	if err != nil {
		return err
	}
	header.flag = Flag(b[0])
	return nil
}
