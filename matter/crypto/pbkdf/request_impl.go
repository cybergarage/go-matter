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
	"github.com/cybergarage/go-matter/matter/crypto"
	"github.com/cybergarage/go-matter/matter/encoding/json"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
)

const (
	initiatorRandomLength = 32
)

var (
	unicastInitiatorSessionID = uint16(0)
)

type paramRequest struct {
	initiatorRandom    []byte
	initiatorSessionID *uint16
	passcodeID         *uint16
	hasPBKDFParameters *bool
	sessionParams      SessionParams
}

// ParamRequestOption defines a functional option for configuring the ParamRequest.
type ParamRequestOption func(*paramRequest)

// WithParamRequestInitiatorSessionID sets the initiator session ID in the ParamRequest.
func WithParamRequestInitiatorSessionID(sessionID uint16) ParamRequestOption {
	return func(r *paramRequest) {
		r.initiatorSessionID = &sessionID
	}
}

// WithParamRequestPasscodeID sets the passcode ID in the ParamRequest.
func WithParamRequestPasscodeID(passcodeID uint16) ParamRequestOption {
	return func(r *paramRequest) {
		r.passcodeID = &passcodeID
	}
}

// WithParamRequestHasPBKDFParameters sets whether the request includes PBKDF parameters.
func WithParamRequestHasPBKDFParameters(hasParams bool) ParamRequestOption {
	return func(r *paramRequest) {
		r.hasPBKDFParameters = &hasParams
	}
}

func WithParamRequestSessionParams(params SessionParams) ParamRequestOption {
	return func(r *paramRequest) {
		r.sessionParams = params
	}
}

func newParamRequest() *paramRequest {
	return &paramRequest{
		initiatorRandom:    nil,
		initiatorSessionID: nil,
		passcodeID:         nil,
		hasPBKDFParameters: nil,
		sessionParams:      nil,
	}
}

// NewParamRequest creates a new PBKDFParamRequest instance.
func NewParamRequest(opts ...ParamRequestOption) ParamRequest {
	r := newParamRequest()
	r.initiatorRandom = crypto.Crypto_DRBG(initiatorRandomLength)
	// 4.13.2.4. Choosing Secure Unicast Session Identifiers
	r.initiatorSessionID = &unicastInitiatorSessionID
	for _, opt := range opts {
		opt(r)
	}
	return r
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

	elem := dec.Element()
	if !elem.Type().IsStructure() {
		return expectedTypeError(tlv.Structure, elem)
	}

	for range 4 {
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
				r.initiatorSessionID = &v
			case 3:
				v, ok := elem.Unsigned2()
				if !ok {
					return expectedTypeError(tlv.UnsignedInt2, elem)
				}
				r.passcodeID = &v
			case 4:
				v, ok := elem.Bool()
				if !ok {
					return expectedTypeError(tlv.BoolTrue, elem)
				}
				r.hasPBKDFParameters = &v
			}
		default:
			return expectedTagError(tlv.TagContext, elem.Tag())
		}
	}

	if err := r.Validate(); err != nil {
		return err
	}

	if !dec.More() {
		return nil
	}

	sessionParams, err := NewSessionFromDecoder(dec)
	if err != nil {
		return err
	}
	r.sessionParams = sessionParams

	return nil
}

// InitiatorRandom returns the initiator random value from the request.
func (r *paramRequest) InitiatorRandom() []byte {
	if r.initiatorRandom == nil {
		return nil
	}
	return r.initiatorRandom
}

// InitiatorSessionID returns the initiator session ID from the request.
func (r *paramRequest) InitiatorSessionID() uint16 {
	if r.initiatorSessionID == nil {
		return 0
	}
	return *r.initiatorSessionID
}

// PasscodeID returns the passcode ID from the request.
func (r *paramRequest) PasscodeID() uint16 {
	if r.passcodeID == nil {
		return 0
	}
	return *r.passcodeID
}

// HasPBKDFParameters indicates whether the request includes PBKDF parameters.
func (r *paramRequest) HasPBKDFParameters() bool {
	if r.hasPBKDFParameters == nil {
		return false
	}
	return *r.hasPBKDFParameters
}

func (r *paramRequest) SessionParams() (SessionParams, bool) {
	if r.sessionParams == nil {
		return nil, false
	}
	return r.sessionParams, true
}

func (r *paramRequest) Validate() error {
	if r.initiatorRandom == nil {
		return newErrMissingRequiredField("initiatorRandom")
	}
	if r.initiatorSessionID == nil {
		return newErrMissingRequiredField("initiatorSessionID")
	}
	if r.passcodeID == nil {
		return newErrMissingRequiredField("passcodeID")
	}
	if r.hasPBKDFParameters == nil {
		return newErrMissingRequiredField("hasPBKDFParameters")
	}
	return nil
}

func (r *paramRequest) Encode(enc tlv.Encoder) error {
	enc.BeginStructure(tlv.NewAnonymousTag())
	if r.initiatorRandom != nil {
		if err := enc.PutBytes(tlv.NewContextTag(1), r.initiatorRandom); err != nil {
			return err
		}
	}
	if r.initiatorSessionID != nil {
		enc.PutUnsigned2(tlv.NewContextTag(2), *r.initiatorSessionID)
	}
	if r.passcodeID != nil {
		enc.PutUnsigned2(tlv.NewContextTag(3), *r.passcodeID)
	}
	if r.hasPBKDFParameters != nil {
		enc.PutBool(tlv.NewContextTag(4), *r.hasPBKDFParameters)
	}
	if r.sessionParams != nil {
		if err := r.sessionParams.Encode(enc); err != nil {
			return err
		}
	}
	if r.sessionParams != nil {
		if err := r.sessionParams.Encode(enc); err != nil {
			return err
		}
	}
	return enc.EndContainer()
}

func (r *paramRequest) Bytes() ([]byte, error) {
	enc := tlv.NewEncoder()
	if err := r.Encode(enc); err != nil {
		return nil, err
	}
	return enc.Bytes(), nil
}

func (r *paramRequest) Map() map[string]any {
	m := make(map[string]any)
	if r.initiatorRandom != nil {
		m["initiator_random"] = r.initiatorRandom
	}
	if r.initiatorSessionID != nil {
		m["initiator_session_id"] = *r.initiatorSessionID
	}
	if r.passcodeID != nil {
		m["passcode_id"] = *r.passcodeID
	}
	if r.hasPBKDFParameters != nil {
		m["has_pbkdf_parameters"] = *r.hasPBKDFParameters
	}
	if r.sessionParams != nil {
		m["session_params"] = r.sessionParams.Map()
	}
	return m
}

func (r *paramRequest) String() string {
	return json.MustMarshal(r.Map())
}
