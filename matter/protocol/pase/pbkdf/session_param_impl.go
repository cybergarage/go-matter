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
	"time"

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
func WithSessionIdleInterval(interval time.Duration) SessionParamsOption {
	return func(s *sessionParams) {
		u := uint32(interval.Milliseconds())
		s.sessionIdleInterval = &u
	}
}

// WithSessionActiveInterval sets the SESSION_ACTIVE_INTERVAL value in the SessionParams.
func WithSessionActiveInterval(interval time.Duration) SessionParamsOption {
	return func(s *sessionParams) {
		u := uint32(interval.Milliseconds())
		s.sessionActiveInterval = &u
	}
}

// WithSessionActiveThreshold sets the SESSION_ACTIVE_THRESHOLD value in the SessionParams.
func WithSessionActiveThreshold(threshold time.Duration) SessionParamsOption {
	return func(s *sessionParams) {
		u := uint16(threshold.Milliseconds())
		s.sessionActiveThreshold = &u
	}
}

// WithDataModelRevision sets the DATA_MODEL_REVISION value in the SessionParams.
func WithDataModelRevision(revision Revision) SessionParamsOption {
	return func(s *sessionParams) {
		s.dataModelRevision = (*uint16)(&revision)
	}
}

// WithInteractionModelRevision sets the INTERACTION_MODEL_REVISION value in the SessionParams.
func WithInteractionModelRevision(revision Revision) SessionParamsOption {
	return func(s *sessionParams) {
		s.interactionModelRevision = (*uint16)(&revision)
	}
}

// WithSpecificationVersion sets the SPECIFICATION_VERSION value in the SessionParams.
func WithSpecificationVersion(version Version) SessionParamsOption {
	return func(s *sessionParams) {
		s.specificationVersion = (*uint32)(&version)
	}
}

// WithMaxPathsPerInvoke sets the MAX_PATHS_PER_INVOKE value in the SessionParams.
func WithMaxPathsPerInvoke(maxPaths uint16) SessionParamsOption {
	return func(s *sessionParams) {
		s.maxPathsPerInvoke = &maxPaths
	}
}

// WithSupportedTransports sets the SUPPORTED_TRANSPORTS value in the SessionParams.
func WithSupportedTransports(transports TransportMode) SessionParamsOption {
	return func(s *sessionParams) {
		s.supportedTransports = (*uint16)(&transports)
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
	s := newSessionParams(
		WithSessionIdleInterval(DefaultSessionIdleDuration),
		WithSessionActiveInterval(DefaultSessionActiveInterval),
		WithSessionActiveThreshold(DefaultSessionActiveThreshold),
		WithDataModelRevision(DefaultDataModelRevision),
		WithInteractionModelRevision(DefaultInteractionModelRevision),
		WithSpecificationVersion(DefaultSpecificationVersion),
		WithMaxPathsPerInvoke(DefaultMaxPathsPerInvoke),
		WithSupportedTransports(DefaultSupportedTransports),
	)
	for _, opt := range opts {
		opt(s)
	}
	return s
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

func (s *sessionParams) SessionIdleInterval() (time.Duration, bool) {
	if s.sessionIdleInterval == nil {
		return 0, false
	}
	return time.Duration(*s.sessionIdleInterval) * time.Millisecond, true
}

func (s *sessionParams) SessionActiveInterval() (time.Duration, bool) {
	if s.sessionActiveInterval == nil {
		return 0, false
	}
	return time.Duration(*s.sessionActiveInterval) * time.Millisecond, true
}

func (s *sessionParams) SessionActiveThreshold() (time.Duration, bool) {
	if s.sessionActiveThreshold == nil {
		return 0, false
	}
	return time.Duration(*s.sessionActiveThreshold) * time.Millisecond, true
}

func (s *sessionParams) DataModelRevision() Revision {
	// 4.13.1. Session Parameters
	// For backwards compatibility, if the DATA_MODEL_REVISION field is missing,
	// it implies a DataModelRevision value of either 16 or 17
	if s.dataModelRevision == nil {
		return DefaultDataModelRevision
	}
	return Revision(*s.dataModelRevision)
}

func (s *sessionParams) InteractionModelRevision() Revision {
	// 4.13.1. Session Parameters
	// For backwards compatibility, if the INTERACTION_MODEL_REVISION field is missing,
	// it implies a value of either 10 or 11.
	if s.interactionModelRevision == nil {
		return DefaultInteractionModelRevision
	}
	return Revision(*s.interactionModelRevision)
}

func (s *sessionParams) SpecificationVersion() Version {
	// 4.13.1. Session Parameters
	// For backwards compatibility, if the SPECIFICATION_VERSION field is missing,
	// it implies a SpecificationVersion value strictly smaller than 0x01030000.
	if s.specificationVersion == nil {
		return DefaultSpecificationVersion
	}
	return Version(*s.specificationVersion)
}

func (s *sessionParams) MaxPathsPerInvoke() uint16 {
	// 4.13.1. Session Parameters
	// For backwards compatibility, if the MAX_PATHS_PER_INVOKE field is missing,
	// it implies a MaxPathsPerInvoke set to 1.
	if s.maxPathsPerInvoke == nil {
		return DefaultMaxPathsPerInvoke
	}
	return *s.maxPathsPerInvoke
}

func (s *sessionParams) SupportedTransports() TransportMode {
	// 4.13.1. Session Parameters
	// For backwards compatibility, if the SUPPORTED_TRANSPORTS field is missing,
	// it implies that the node only supports MRP.
	if s.supportedTransports == nil {
		return DefaultSupportedTransports
	}
	return TransportMode(*s.supportedTransports)
}

func (s *sessionParams) MaxTCPMessageSize() (uint32, bool) {
	// 4.13.1. Session Parameters
	// The MAX_TCP_MESSAGE_SIZE field SHALL only be present
	// if the SUPPORTED_TRANSPORTS field indicates that TCP is supported.
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

func (s *sessionParams) Encode(enc tlv.Encoder, tagNum uint8) error {
	enc.BeginStructure(tlv.NewContextTag(tagNum))
	if s.sessionIdleInterval != nil {
		enc.PutUnsigned4(tlv.NewContextTag(1), *s.sessionIdleInterval)
	}
	if s.sessionActiveInterval != nil {
		enc.PutUnsigned4(tlv.NewContextTag(2), *s.sessionActiveInterval)
	}
	if s.sessionActiveThreshold != nil {
		enc.PutUnsigned2(tlv.NewContextTag(3), *s.sessionActiveThreshold)
	}
	if s.dataModelRevision != nil {
		enc.PutUnsigned2(tlv.NewContextTag(4), *s.dataModelRevision)
	}
	if s.interactionModelRevision != nil {
		enc.PutUnsigned2(tlv.NewContextTag(5), *s.interactionModelRevision)
	}
	if s.specificationVersion != nil {
		enc.PutUnsigned4(tlv.NewContextTag(6), *s.specificationVersion)
	}
	if s.maxPathsPerInvoke != nil {
		enc.PutUnsigned2(tlv.NewContextTag(7), *s.maxPathsPerInvoke)
	}
	if s.supportedTransports != nil {
		enc.PutUnsigned2(tlv.NewContextTag(8), *s.supportedTransports)
	}
	if s.maxTCPMessageSize != nil {
		enc.PutUnsigned4(tlv.NewContextTag(9), *s.maxTCPMessageSize)
	}
	return enc.EndContainer()
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
