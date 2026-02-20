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
	responderRandomLength = 32
)

type paramResponse struct {
	initiatorRandom        []byte
	responderRandom        []byte
	responderSessionID     *uint16
	params                 Params
	responderSessionParams SessionParams
}

// ParamResponseOption defines a functional option for configuring the ParamResponse.
type ParamResponseOption func(*paramResponse)

func newParamResponse(opts ...ParamResponseOption) *paramResponse {
	r := &paramResponse{
		initiatorRandom:        nil,
		responderRandom:        nil,
		responderSessionID:     nil,
		params:                 nil,
		responderSessionParams: nil,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// WithParamResponseParamRequest sets the initiator random in the ParamResponse based on the given ParamRequest.
func WithParamResponseParamRequest(req ParamRequest) ParamResponseOption {
	return func(r *paramResponse) {
		r.initiatorRandom = req.InitiatorRandom()
	}
}

// WithParamResponseInitiatorRandom sets the initiator random in the ParamResponse.
func WithParamResponseInitiatorRandom(random []byte) ParamResponseOption {
	return func(r *paramResponse) {
		r.initiatorRandom = random
	}
}

// WithParamResponseResponderRandom sets the responder random in the ParamResponse.
func WithParamResponseResponderRandom(random []byte) ParamResponseOption {
	return func(r *paramResponse) {
		r.responderRandom = random
	}
}

// WithParamResponseResponderSessionID sets the responder session ID in the ParamResponse.
func WithParamResponseResponderSessionID(sessionID uint16) ParamResponseOption {
	return func(r *paramResponse) {
		r.responderSessionID = &sessionID
	}
}

// WithParamResponsePBKDFParams sets the PBKDF parameters in the ParamResponse.
func WithParamResponsePBKDFParams(params Params) ParamResponseOption {
	return func(r *paramResponse) {
		r.params = params
	}
}

// WithParamResponseResponderSessionParams sets the responder session parameters in the ParamResponse.
func WithParamResponseResponderSessionParams(sessionParams SessionParams) ParamResponseOption {
	return func(r *paramResponse) {
		r.responderSessionParams = sessionParams
	}
}

// NewParamResponse returns a new ParamResponse instance configured with the provided options.
func NewParamResponse(opts ...ParamResponseOption) ParamResponse {
	r := newParamResponse(opts...)
	// 4.14.1. Passcode-Authenticated Session Establishment (PASE)
	if r.responderRandom == nil {
		r.responderRandom = crypto.Crypto_DRBG(responderRandomLength)
	}
	if r.responderSessionID == nil {
		// 4.13.2.4. Choosing Secure Unicast Session Identifiers
		r.responderSessionID = &unicastSessionID
	}

	return r
}

// NewParamResponseFromBytes returns a new PBKDFParamResponse instance parsed from the given byte slice.
func NewParamResponseFromBytes(data []byte) (ParamResponse, error) {
	r := newParamResponse()
	if err := r.ParseBytes(data); err != nil {
		return nil, err
	}
	return r, nil
}

// ParseBytes parses the given byte slice into the PBKDFParamResponse structure.
func (r *paramResponse) ParseBytes(data []byte) error {
	return r.Decode(tlv.NewDecoderWithBytes(data))
}

func (r *paramResponse) InitiatorRandom() []byte {
	return r.initiatorRandom
}

func (r *paramResponse) ResponderRandom() []byte {
	return r.responderRandom
}

func (r *paramResponse) ResponderSessionID() uint16 {
	if r.responderSessionID == nil {
		return 0
	}
	return *r.responderSessionID
}

func (r *paramResponse) PBKDFParams() Params {
	return r.params
}

func (r *paramResponse) ResponderSessionParams() (SessionParams, bool) {
	if r.responderSessionParams == nil {
		return nil, false
	}
	return r.responderSessionParams, true
}

// Decode decodes the given TLV decoder into the ParamResponse structure.
func (r *paramResponse) Decode(dec tlv.Decoder) error {
	// 4.14.1.2. Protocol Details
	// pbkdfparamresp-struct => STRUCTURE [ tag-order ]
	// {
	//   initiatorRandom [1] : OCTET STRING [ length 32 ],
	//   responderRandom [2] : OCTET STRING [ length 32 ],
	//   responderSessionId [3] : UNSIGNED INTEGER [ range 16-bits ],
	//   pbkdf_parameters [4] : Crypto_PBKDFParameterSet,
	//   responderSessionParams [5, optional] : session-parameter-struct
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
				b, ok := elem.Bytes()
				if !ok {
					return expectedTypeError(tlv.OctetString1, elem)
				}
				r.responderRandom = b
			case 3:
				v, ok := elem.Unsigned2()
				if !ok {
					return expectedTypeError(tlv.UnsignedInt2, elem)
				}
				r.responderSessionID = &v
			case 4:
				v, err := NewParamsFromDecoder(dec)
				if err != nil {
					return err
				}
				r.params = v
			default:
				return expectedTagError(tlv.TagContext, elem.Tag())
			}
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
	r.responderSessionParams = sessionParams

	return nil
}

func (r *paramResponse) Validate() error {
	if err := checkInitiatorRandomLength("initiatorRandom", r.initiatorRandom, initiatorRandomLength); err != nil {
		return err
	}
	if err := checkInitiatorRandomLength("responderRandom", r.responderRandom, responderRandomLength); err != nil {
		return err
	}
	if r.responderSessionID == nil {
		return newErrMissingRequiredField("responderSessionID")
	}
	if r.params == nil {
		return newErrMissingRequiredField("params")
	}
	return nil
}

// Encode encodes the ParamResponse into the given TLV encoder.
func (r *paramResponse) Encode(enc tlv.Encoder) error {
	if err := r.Validate(); err != nil {
		return err
	}

	// initiatorRandom        []byte
	// responderRandom        []byte
	// responderSessionID     *uint16
	// params                 Params
	// responderSessionParams SessionParams

	enc.BeginStructure(tlv.NewAnonymousTag())
	if r.initiatorRandom != nil {
		if err := enc.PutOctet(tlv.NewContextTag(1), r.initiatorRandom); err != nil {
			return err
		}
	}
	if r.responderRandom != nil {
		if err := enc.PutOctet(tlv.NewContextTag(2), r.responderRandom); err != nil {
			return err
		}
	}
	if r.responderSessionID != nil {
		enc.PutUnsigned2(tlv.NewContextTag(3), *r.responderSessionID)
	}
	if err := CryptoPBKDFParameterSet(enc, 4, r.params); err != nil {
		return err
	}
	if r.responderSessionParams != nil {
		if err := r.responderSessionParams.Encode(enc, 5); err != nil {
			return err
		}
	}
	return enc.EndContainer()
}

// Bytes returns the byte representation of the ParamResponse message, ready for transmission.
func (r *paramResponse) Bytes() ([]byte, error) {
	enc := tlv.NewEncoder()
	if err := r.Encode(enc); err != nil {
		return nil, err
	}
	return enc.Bytes(), nil
}

func (r *paramResponse) Map() map[string]any {
	m := make(map[string]any)
	if r.initiatorRandom != nil {
		m["initiator_random"] = r.initiatorRandom
	}
	if r.responderRandom != nil {
		m["responder_random"] = r.responderRandom
	}
	if r.responderSessionID != nil {
		m["responder_session_id"] = *r.responderSessionID
	}
	if r.params != nil {
		m["pbkdf_parameters"] = r.params.Map()
	}
	if r.responderSessionParams != nil {
		m["responder_session_params"] = r.responderSessionParams.Map()
	}
	return m
}

func (r *paramResponse) String() string {
	return json.MustMarshal(r.Map())
}
