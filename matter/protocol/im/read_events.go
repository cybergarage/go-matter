// Copyright (C) 2026 The go-matter Authors. All rights reserved.
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

package im

import (
	"errors"
	"fmt"

	"github.com/cybergarage/go-matter/matter/encoding/message"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
)

// ReadEventsOption configures ReadEvents.
type ReadEventsOption func(*readEventsConfig)

type readEventsConfig struct {
	eventMin       uint64
	hasEventMin    bool
	fabricFiltered bool
}

// WithReadEventMin reads the events numbered n and up only (10.6.6).
func WithReadEventMin(n uint64) ReadEventsOption {
	return func(c *readEventsConfig) {
		c.eventMin, c.hasEventMin = n, true
	}
}

// WithReadEventsFabricFiltered sets IsFabricFiltered, which limits
// fabric-sensitive events to this node's fabric. Defaults to true.
func WithReadEventsFabricFiltered(filtered bool) ReadEventsOption {
	return func(c *readEventsConfig) {
		c.fabricFiltered = filtered
	}
}

// ReadEvents reads the events of paths the node keeps (8.4. Read
// Interaction, 7.14. Event), joining the chunks of the report.
func ReadEvents(sess SecureSession, paths []EventRequestPath, opts ...ReadEventsOption) ([]EventReport, error) {
	if len(paths) == 0 {
		return nil, errors.New("im: ReadEvents: no event path")
	}
	cfg := readEventsConfig{eventMin: 0, hasEventMin: false, fabricFiltered: true}
	for _, opt := range opts {
		opt(&cfg)
	}
	payload, err := encodeReadEventsRequest(paths, cfg)
	if err != nil {
		return nil, fmt.Errorf("im: build ReadRequest: %w", err)
	}
	exchange := newExchangeID(sess)
	if err := transmitOnExchange(sess, message.ReadRequestMessage, exchange, payload); err != nil {
		return nil, fmt.Errorf("im: transmit ReadRequest: %w", err)
	}
	var events []EventReport
	var timeline eventTimeline
	for {
		raw, err := receiveExchangeResponse(sess, exchange)
		if err != nil {
			return nil, fmt.Errorf("im: ReadEvents: %w", err)
		}
		hdr, err := message.NewProtocolHeaderFromBytes(raw)
		if err != nil {
			return nil, fmt.Errorf("im: ReadEvents: %w", err)
		}
		if hdr.Opcode().IsStatusResponseMessage() {
			body, err := messageBody(raw, hdr)
			if err != nil {
				return nil, err
			}
			status, err := parseStatusResponseMessage(body)
			if err != nil {
				return nil, fmt.Errorf("im: ReadEvents: %w", err)
			}
			return nil, fmt.Errorf("im: ReadEvents: refused with status 0x%02X", status.IMStatus)
		}
		if !hdr.Opcode().IsReportDataMessage() {
			return nil, fmt.Errorf("im: ReadEvents: unexpected opcode %v", hdr.Opcode())
		}
		rd, err := decodeReportData(raw)
		if err != nil {
			return nil, err
		}
		if err := resolveEventTimestamps(&timeline, rd.events); err != nil {
			return nil, fmt.Errorf("im: ReadEvents: %w", err)
		}
		events = append(events, rd.events...)
		// Each chunk but the last, and a last one which asks for it, is
		// answered (8.4.2).
		if rd.moreChunks || !rd.suppressResponse {
			if err := transmitOnExchange(sess, message.StatusResponseMessage, exchange, statusResponsePayload(StatusSuccess)); err != nil {
				return nil, fmt.Errorf("im: ReadEvents: answer a report: %w", err)
			}
		}
		if !rd.moreChunks {
			return events, nil
		}
	}
}

// encodeReadEventsRequest encodes a ReadRequestMessage for events (10.7.2).
func encodeReadEventsRequest(paths []EventRequestPath, cfg readEventsConfig) ([]byte, error) {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	if err := encodeEventRequests(enc, tlv.NewContextTag(1), paths); err != nil {
		return nil, err
	}
	if cfg.hasEventMin {
		if err := encodeEventFilters(enc, tlv.NewContextTag(2), cfg.eventMin); err != nil {
			return nil, err
		}
	}
	enc.PutBool(tlv.NewContextTag(3), cfg.fabricFiltered)
	enc.PutUnsigned1(tlv.NewContextTag(interactionModelRevisionTag), interactionModelRevision)
	if err := enc.EndContainer(); err != nil {
		return nil, err
	}
	return enc.Bytes(), nil
}
