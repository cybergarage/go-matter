// Copyright (C) 2024 The go-matter Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tlv

import (
	"errors"
)

// Centralized error variables returned by encoder/decoder operations.
var (
	// ErrUnexpectedEOF indicates the buffer ended prematurely.
	ErrUnexpectedEOF = errors.New("tlv: unexpected EOF")
	// ErrInvalidControlByte indicates an unrecognized or malformed control octet.
	ErrInvalidControlByte = errors.New("tlv: invalid control byte")
	// ErrUnknownElementType indicates an element type code not supported by this implementation.
	ErrUnknownElementType = errors.New("tlv: unknown or unsupported element type")
	// ErrContainerStackEmpty indicates an EndContainer was attempted with no open container.
	ErrContainerStackEmpty = errors.New("tlv: container stack underflow")
	// ErrBooleanMismatch is reserved (not currently used in this version).
	ErrBooleanMismatch = errors.New("tlv: boolean element type mismatch")
	// ErrNullHasValue would be used if a null payload incorrectly included data.
	ErrNullHasValue = errors.New("tlv: null element must not carry payload")
	// ErrStringLengthOverflow indicates an encoded string length exceeded supported range.
	ErrStringLengthOverflow = errors.New("tlv: string length exceeds representable field")
	// ErrTagUnsupportedForm indicates an unsupported TagControl form was requested.
	ErrTagUnsupportedForm = errors.New("tlv: unsupported tag control form")
	// ErrDecodeTagLength indicates insufficient bytes while decoding a tag field.
	ErrDecodeTagLength = errors.New("tlv: insufficient bytes for tag")
)
