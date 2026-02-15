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
	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
)

type paramRequest struct {
}

// NewParamRequest creates a new PBKDFParamRequest instance.
func NewParamRequest() ParamRequest {
	return &paramRequest{}
}

// NewParamRequestFromBytes returns a new PBKDFParamRequest instance parsed from the given byte slice.
func NewParamRequestFromBytes(data []byte) (ParamRequest, error) {
	r := &paramRequest{}
	if err := r.ParseBytes(data); err != nil {
		return nil, err
	}
	return r, nil
}

// ParseBytes parses the given byte slice into the PBKDFParamRequest structure.
func (r *paramRequest) ParseBytes(data []byte) error {
	// 4.14.1.2. Protocol Details

	dec := tlv.NewDecoder(data)

	for dec.Next() {
		elem := dec.Element()
		// We can ignore the contents of the ParamRequest for now, as it's often empty.
		// If needed, we can add parsing logic here to extract specific fields in the future.
		log.Debugf("Parsed TLV element: %s", elem.String())
	}

	if err := dec.Err(); err != nil {
		return err
	}

	return nil
}

// Bytes encodes the ParamRequest into its byte representation for transmission.
func (r *paramRequest) Bytes() ([]byte, error) {
	enc := tlv.NewEncoder()
	enc.StartStructure(tlv.AnonymousTag())

	// TODO(spec): Add mandatory fields if the target device requires them
	// (e.g., initiator random, session parameters, etc.).
	// Keeping this structure empty is useful as a first connectivity probe.

	if err := enc.EndContainer(); err != nil {
		return nil, err
	}
	enc.MustEndAll()
	return enc.Bytes(), nil
}
