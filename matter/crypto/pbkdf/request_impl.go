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

	"github.com/cybergarage/go-matter/matter/crypto"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
)

const (
	initiatorRandomLength     = 32
	unicastInitiatorSessionID = 0
)

type paramRequest struct {
	initiatorRandom    []byte
	initiatorSessionID uint16
	passcodeID         uint16
	hasPBKDFParameters bool
}

// ParamRequestOption defines a functional option for configuring the ParamRequest.
type ParamRequestOption func(*paramRequest)

// WithParamRequestInitiatorSessionID sets the initiator session ID in the ParamRequest.
func WithParamRequestInitiatorSessionID(sessionID uint16) ParamRequestOption {
	return func(r *paramRequest) {
		r.initiatorSessionID = sessionID
	}
}

// WithParamRequestPasscodeID sets the passcode ID in the ParamRequest.
func WithParamRequestPasscodeID(passcodeID uint16) ParamRequestOption {
	return func(r *paramRequest) {
		r.passcodeID = passcodeID
	}
}

// WithParamRequestHasPBKDFParameters sets whether the request includes PBKDF parameters.
func WithParamRequestHasPBKDFParameters(hasParams bool) ParamRequestOption {
	return func(r *paramRequest) {
		r.hasPBKDFParameters = hasParams
	}
}

// NewParamRequest creates a new PBKDFParamRequest instance.
func NewParamRequest(opts ...ParamRequestOption) ParamRequest {
	r := newParamRequest()
	r.initiatorRandom = crypto.Crypto_DRBG(initiatorRandomLength)
	// 4.13.2.4. Choosing Secure Unicast Session Identifiers
	r.initiatorSessionID = unicastInitiatorSessionID
	for _, opt := range opts {
		opt(r)
	}
	return r
}

func newParamRequest() *paramRequest {
	return &paramRequest{
		initiatorRandom:    []byte{},
		initiatorSessionID: 0,
		passcodeID:         0,
		hasPBKDFParameters: false,
	}
}

// NewParamRequestFromBytes returns a new PBKDFParamRequest instance parsed from the given byte slice.
func NewParamRequestFromBytes(data []byte) (ParamRequest, error) {
	r := newParamRequest()
	if err := r.ParseBytes(data); err != nil {
		return nil, err
	}
	return r, nil
}

// ParseBytes parses the given byte slice into the PBKDFParamRequest structure.
func (r *paramRequest) ParseBytes(data []byte) error {
	return r.Decode(tlv.NewDecoderWithBytes(data))
}

// Decode decodes the given TLV decoder into the ParamRequest structure.
func (r *paramRequest) Decode(dec tlv.Decoder) error {
	expectedTypeError := func(expected tlv.ElementType, actual tlv.Element) error {
		return fmt.Errorf("expected %s, got %s", expected, actual.Type())
	}

	exptectedTagError := func(expected tlv.TagControl, actual tlv.Tag) error {
		return fmt.Errorf("expected tag type %s, got %s", expected, actual.Control())
	}

	if !dec.Next() {
		return dec.Error()
	}

	elem := dec.Element()
	if !elem.Type().IsStructure() {
		return expectedTypeError(tlv.Structure, elem)
	}

	// 4.14.1.2. Protocol Details
	// pbkdfparamreq-struct => STRUCTURE [ tag-order ]
	// {
	//   initiatorRandom [1] : OCTET STRING [ length 32 ],
	//   initiatorSessionId [2] : UNSIGNED INTEGER [ range 16-bits ],
	//   passcodeId [3] : UNSIGNED INTEGER [ length 16-bits ],
	//   hasPBKDFParameters [4] : BOOLEAN,
	//   initiatorSessionParams [5, optional] : session-parameter-struct
	// }

	if !dec.Next() {
		return dec.Error()
	}
	elem = dec.Element()
	switch t := elem.Tag().(type) {
	case tlv.ContextTag:
		switch t.ContextNumber() {
		case 1:
			b, ok := elem.Bytes()
			if !ok {
				return expectedTypeError(tlv.OctetString1, elem)
			}
			r.initiatorRandom = b
		case 2:
			v, ok := elem.Unsigned2()
			if !ok {
				return expectedTypeError(tlv.UnsignedInt2, elem)
			}
			r.initiatorSessionID = v
		case 3:
			v, ok := elem.Unsigned2()
			if !ok {
				return expectedTypeError(tlv.UnsignedInt2, elem)
			}
			r.passcodeID = v
		case 4:
			v, ok := elem.Bool()
			if !ok {
				return expectedTypeError(tlv.BoolTrue, elem)
			}
			r.hasPBKDFParameters = v
		}
	default:
		return exptectedTagError(tlv.TagContext, elem.Tag())
	}

	if !dec.Next() {
		return nil
	}

	return nil
}

// InitiatorRandom returns the initiator random value from the request.
func (r *paramRequest) InitiatorRandom() []byte {
	return r.initiatorRandom
}

// InitiatorSessionID returns the initiator session ID from the request.
func (r *paramRequest) InitiatorSessionID() uint16 {
	return r.initiatorSessionID
}

// PasscodeID returns the passcode ID from the request.
func (r *paramRequest) PasscodeID() uint16 {
	return r.passcodeID
}

// HasPBKDFParameters indicates whether the request includes PBKDF parameters.
func (r *paramRequest) HasPBKDFParameters() bool {
	return r.hasPBKDFParameters
}

// Bytes encodes the ParamRequest into its byte representation for transmission.
func (r *paramRequest) Bytes() ([]byte, error) {
	enc := tlv.NewEncoder()
	enc.StartStructure(tlv.NewAnonymousTag())

	// TODO(spec): Add mandatory fields if the target device requires them
	// (e.g., initiator random, session parameters, etc.).
	// Keeping this structure empty is useful as a first connectivity probe.

	if err := enc.EndContainer(); err != nil {
		return nil, err
	}
	enc.MustEndAll()
	return enc.Bytes(), nil
}
