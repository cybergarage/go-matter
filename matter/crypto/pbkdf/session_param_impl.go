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
	"github.com/cybergarage/go-matter/matter/encoding/json"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
)

type sessionParams struct {
	sessionIdleInterval      *uint32
	sessionActiveInterval    *uint32
	sessionActiveThreshold   *uint16
	dataModelRevision        *uint16
	interactionModelRevision *uint16
	specificationVersion     *uint32
	maxPathsPerInvoke        *uint16
	supportedTransports      *uint16
	maxTCPMessageSize        *uint32
}

// SessionParamsOption defines a functional option for configuring the SessionParams.
type SessionParamsOption func(*sessionParams)

// WithSessionIdleInterval sets the SESSION_IDLE_INTERVAL value in the SessionParams.
func WithSessionIdleInterval(interval uint32) SessionParamsOption {
	return func(s *sessionParams) {
		s.sessionIdleInterval = &interval
	}
}

// WithSessionActiveInterval sets the SESSION_ACTIVE_INTERVAL value in the SessionParams.
func WithSessionActiveInterval(interval uint32) SessionParamsOption {
	return func(s *sessionParams) {
		s.sessionActiveInterval = &interval
	}
}

// WithSessionActiveThreshold sets the SESSION_ACTIVE_THRESHOLD value in the SessionParams.
func WithSessionActiveThreshold(threshold uint16) SessionParamsOption {
	return func(s *sessionParams) {
		s.sessionActiveThreshold = &threshold
	}
}

// WithDataModelRevision sets the DATA_MODEL_REVISION value in the SessionParams.
func WithDataModelRevision(revision uint16) SessionParamsOption {
	return func(s *sessionParams) {
		s.dataModelRevision = &revision
	}
}

// WithInteractionModelRevision sets the INTERACTION_MODEL_REVISION value in the SessionParams.
func WithInteractionModelRevision(revision uint16) SessionParamsOption {
	return func(s *sessionParams) {
		s.interactionModelRevision = &revision
	}
}

// WithSpecificationVersion sets the SPECIFICATION_VERSION value in the SessionParams.
func WithSpecificationVersion(version uint32) SessionParamsOption {
	return func(s *sessionParams) {
		s.specificationVersion = &version
	}
}

// WithMaxPathsPerInvoke sets the MAX_PATHS_PER_INVOKE value in the SessionParams.
func WithMaxPathsPerInvoke(maxPaths uint16) SessionParamsOption {
	return func(s *sessionParams) {
		s.maxPathsPerInvoke = &maxPaths
	}
}

// WithSupportedTransports sets the SUPPORTED_TRANSPORTS value in the SessionParams.
func WithSupportedTransports(transports uint16) SessionParamsOption {
	return func(s *sessionParams) {
		s.supportedTransports = &transports
	}
}

// WithMaxTCPMessageSize sets the MAX_TCP_MESSAGE_SIZE value in the SessionParams.
func WithMaxTCPMessageSize(size uint32) SessionParamsOption {
	return func(s *sessionParams) {
		s.maxTCPMessageSize = &size
	}
}

func newSessionParams(opts ...SessionParamsOption) *sessionParams {
	s := &sessionParams{
		sessionIdleInterval:      nil,
		sessionActiveInterval:    nil,
		sessionActiveThreshold:   nil,
		dataModelRevision:        nil,
		interactionModelRevision: nil,
		specificationVersion:     nil,
		maxPathsPerInvoke:        nil,
		supportedTransports:      nil,
		maxTCPMessageSize:        nil,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// NewSessionParams creates a new SessionParams instance with the provided options.
func NewSessionParams(opts ...SessionParamsOption) SessionParams {
	return newSessionParams(opts...)
}

// NewSessionFromDecoder returns a new SessionParams instance parsed from the given TLV decoder.
func NewSessionFromDecoder(dec tlv.Decoder) (SessionParams, error) {
	s := newSessionParams()
	return s, s.Decode(dec)
}

// Decode decodes the given TLV decoder into the SessionParams structure.
func (s *sessionParams) Decode(dec tlv.Decoder) error {
	// 4.13.1. Session Parameters
	// session-parameter-struct => STRUCTURE [ tag-order ]
	// {
	//   SESSION_IDLE_INTERVAL [1, optional] : UNSIGNED INTEGER [ range 32-bits ],
	//   SESSION_ACTIVE_INTERVAL [2, optional] : UNSIGNED INTEGER [ range 32-bits ],
	//   SESSION_ACTIVE_THRESHOLD [3, optional] : UNSIGNED INTEGER [ range 16-bits ],
	//   DATA_MODEL_REVISION [4] : UNSIGNED INTEGER [ range 16-bits ],
	//   INTERACTION_MODEL_REVISION [5] : UNSIGNED INTEGER [ range 16-bits ],
	//   SPECIFICATION_VERSION [6] : UNSIGNED INTEGER [ range 32-bits ],
	//   MAX_PATHS_PER_INVOKE [7] : UNSIGNED INTEGER [ range 16-bits ],
	//   SUPPORTED_TRANSPORTS [8] : UNSIGNED INTEGER [ range 16-bits ],
	//   MAX_TCP_MESSAGE_SIZE [9, optional] : UNSIGNED INTEGER [ range 32-bits ],
	// }

	if !dec.Next() {
		return dec.Error()
	}

	elem := dec.Element()
	if !elem.Type().IsStructure() {
		return expectedTypeError(tlv.Structure, elem)
	}

	for dec.Next() {
		elem = dec.Element()
		switch t := elem.Tag().(type) {
		case tlv.ContextTag:
			switch t.ContextNumber() {
			case 1:
				v, ok := elem.Unsigned4()
				if !ok {
					return expectedTypeError(tlv.UnsignedInt4, elem)
				}
				s.sessionIdleInterval = &v
			case 2:
				v, ok := elem.Unsigned4()
				if !ok {
					return expectedTypeError(tlv.UnsignedInt4, elem)
				}
				s.sessionActiveInterval = &v
			case 3:
				v, ok := elem.Unsigned2()
				if !ok {
					return expectedTypeError(tlv.UnsignedInt2, elem)
				}
				s.sessionActiveThreshold = &v
			case 4:
				v, ok := elem.Unsigned2()
				if !ok {
					return expectedTypeError(tlv.UnsignedInt2, elem)
				}
				s.dataModelRevision = &v
			case 5:
				v, ok := elem.Unsigned2()
				if !ok {
					return expectedTypeError(tlv.UnsignedInt2, elem)
				}
				s.interactionModelRevision = &v
			case 6:
				v, ok := elem.Unsigned4()
				if !ok {
					return expectedTypeError(tlv.UnsignedInt4, elem)
				}
				s.specificationVersion = &v
			case 7:
				v, ok := elem.Unsigned2()
				if !ok {
					return expectedTypeError(tlv.UnsignedInt2, elem)
				}
				s.maxPathsPerInvoke = &v
			case 8:
				v, ok := elem.Unsigned2()
				if !ok {
					return expectedTypeError(tlv.UnsignedInt2, elem)
				}
				s.supportedTransports = &v
			case 9:
				v, ok := elem.Unsigned4()
				if !ok {
					return expectedTypeError(tlv.UnsignedInt4, elem)
				}
				s.maxTCPMessageSize = &v
			}
		default:
			return expectedTagError(tlv.TagContext, elem.Tag())
		}
	}

	if err := dec.Error(); err != nil {
		return err
	}

	if err := s.Validiate(); err != nil {
		return err
	}

	return nil
}

func (s *sessionParams) SessionIdleInterval() (uint32, bool) {
	if s.sessionIdleInterval == nil {
		return 0, false
	}
	return *s.sessionIdleInterval, true
}

func (s *sessionParams) SessionActiveInterval() (uint32, bool) {
	if s.sessionActiveInterval == nil {
		return 0, false
	}
	return *s.sessionActiveInterval, true
}

func (s *sessionParams) SessionActiveThreshold() (uint16, bool) {
	if s.sessionActiveThreshold == nil {
		return 0, false
	}
	return *s.sessionActiveThreshold, true
}

func (s *sessionParams) DataModelRevision() uint16 {
	if s.dataModelRevision == nil {
		return 0
	}
	return *s.dataModelRevision
}

func (s *sessionParams) InteractionModelRevision() uint16 {
	if s.interactionModelRevision == nil {
		return 0
	}
	return *s.interactionModelRevision
}

func (s *sessionParams) SpecificationVersion() uint32 {
	// 4.13.1. Session Parameters
	if s.specificationVersion == nil {
		return 0
	}
	return *s.specificationVersion
}

func (s *sessionParams) MaxPathsPerInvoke() uint16 {
	// 4.13.1. Session Parameters
	if s.maxPathsPerInvoke == nil {
		return 0
	}
	return *s.maxPathsPerInvoke
}

func (s *sessionParams) SupportedTransports() uint16 {
	// 4.13.1. Session Parameters
	// For backwards compatibility, if the SUPPORTED_TRANSPORTS field is missing, it implies that the node only supports MRP.
	if s.supportedTransports == nil {
		return uint16(MRP)
	}
	return *s.supportedTransports
}

func (s *sessionParams) MaxTCPMessageSize() (uint32, bool) {
	if s.maxTCPMessageSize == nil {
		return 0, false
	}
	return *s.maxTCPMessageSize, true
}

func (s *sessionParams) Validiate() error {
	if s.dataModelRevision == nil {
		return newErrMissingRequiredField("data_model_revision")
	}
	if s.interactionModelRevision == nil {
		return newErrMissingRequiredField("interaction_model_revision")
	}
	if s.specificationVersion == nil {
		return newErrMissingRequiredField("specification_version")
	}
	if s.maxPathsPerInvoke == nil {
		return newErrMissingRequiredField("max_paths_per_invoke")
	}
	return nil
}

func (s *sessionParams) Map() map[string]any {
	m := make(map[string]any)
	if s.sessionIdleInterval != nil {
		m["session_idle_interval"] = *s.sessionIdleInterval
	}
	if s.sessionActiveInterval != nil {
		m["session_active_interval"] = *s.sessionActiveInterval
	}
	if s.sessionActiveThreshold != nil {
		m["session_active_threshold"] = *s.sessionActiveThreshold
	}
	if s.dataModelRevision != nil {
		m["data_model_revision"] = *s.dataModelRevision
	}
	if s.interactionModelRevision != nil {
		m["interaction_model_revision"] = *s.interactionModelRevision
	}
	if s.specificationVersion != nil {
		m["specification_version"] = *s.specificationVersion
	}
	if s.maxPathsPerInvoke != nil {
		m["max_paths_per_invoke"] = *s.maxPathsPerInvoke
	}
	if s.supportedTransports != nil {
		m["supported_transports"] = *s.supportedTransports
	}
	if s.maxTCPMessageSize != nil {
		m["max_tcp_message_size"] = *s.maxTCPMessageSize
	}
	return m
}

func (s *sessionParams) String() string {
	return json.MustMarshal(s.Map())
}
