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

package pbkdf

import (
	"fmt"

	"github.com/cybergarage/go-matter/matter/encoding/tlv"
)

type paramResponse struct {
	iterations uint32
	salt       []byte
}

// NewParamResponseFromBytes returns a new PBKDFParamResponse instance parsed from the given byte slice.
func NewParamResponseFromBytes(tlvBytes []byte) (ParamResponse, error) {
	dec := tlv.NewDecoderWithBytes(tlvBytes)
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
	if dec.Error() != nil {
		return nil, dec.Error()
	}

	// If these are missing, it most likely means our assumed context tag numbers
	// do not match the device/spec. Dump the full TLV to determine the correct mapping.
	if iter == 0 || len(salt) == 0 {
		return nil, fmt.Errorf("PBKDFParamResponse missing fields: iter=%d saltLen=%d", iter, len(salt))
	}
	return &paramResponse{iterations: iter, salt: salt}, nil
}

// Iterations returns the number of iterations specified in the PBKDFParamResponse.
func (r *paramResponse) Iterations() uint32 {
	return r.iterations
}

// Salt returns the salt value specified in the PBKDFParamResponse.
func (r *paramResponse) Salt() []byte {
	return r.salt
}

// Bytes returns the byte representation of the ParamResponse message, ready for transmission.
func (r *paramResponse) Bytes() ([]byte, error) {
	return nil, fmt.Errorf("encoding ParamResponse to bytes is not implemented yet")
}
