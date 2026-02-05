// Copyright (C) 2025 The go-matter Authors. All rights reserved.
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

package pase

import (
	"fmt"

	"github.com/cybergarage/go-matter/matter/encoding/tlv"
)

// PBKDFParamRequest/Response fields are defined by the Matter specification using
// context-specific tag numbers. We will confirm the exact tag numbers by inspecting
// the device response TLV (DebugTLV) and then locking these constants down.
const (
	pbkdfTagIterations = 1
	pbkdfTagSalt       = 2
)

// PBKDFParamResponse represents a PBKDF parameter response.
type PBKDFParamResponse struct {
	Iterations uint32
	Salt       []byte
}

// EncodePBKDFParamRequest encodes a PBKDF parameter request.
func EncodePBKDFParamRequest() ([]byte, error) {
	enc := tlv.NewEncoder()
	enc.StartStructure(tlv.AnonymousTag())

	// TODO(spec): Add mandatory fields if the target device requires them
	// (e.g., initiator random, session parameters, etc.).
	// Keeping this structure empty is useful as a first connectivity probe.

	if err := enc.EndContainer(); err != nil {
		return nil, err
	}
	enc.MustEndAll()
	return append([]byte{opPBKDFParamRequest}, enc.Bytes()...), nil
}

// DecodePBKDFParamResponse decodes a PBKDF parameter response.
func DecodePBKDFParamResponse(b []byte) (*PBKDFParamResponse, error) {
	if len(b) < 1 || b[0] != opPBKDFParamResponse {
		return nil, fmt.Errorf("unexpected opcode or empty response")
	}
	tlvBytes := b[1:]

	dec := tlv.NewDecoder(tlvBytes)
	var (
		iter uint32
		salt []byte
	)
	for dec.Next() {
		el := dec.Element()
		tagNum, ok := tlv.NewContextNumberFromTag(el.Tag())
		if !ok {
			continue
		}
		switch tagNum {
		case pbkdfTagIterations:
			if u, ok := el.Unsigned(); ok {
				iter = uint32(u)
			}
		case pbkdfTagSalt:
			if bs, ok := el.Bytes(); ok {
				salt = bs
			}
		}
	}
	if dec.Err() != nil {
		return nil, dec.Err()
	}

	// If these are missing, it most likely means our assumed context tag numbers
	// do not match the device/spec. Dump the full TLV to determine the correct mapping.
	if iter == 0 || len(salt) == 0 {
		return nil, fmt.Errorf("PBKDFParamResponse missing fields: iter=%d saltLen=%d", iter, len(salt))
	}
	return &PBKDFParamResponse{Iterations: iter, Salt: salt}, nil
}
