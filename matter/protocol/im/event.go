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
	"time"

	"github.com/cybergarage/go-matter/matter/encoding/tlv"
)

// EventID identifies an event of a cluster (7.14. Event).
type EventID uint32

// EventPriority is the priority of an event (7.14.2.1).
type EventPriority uint8

// Event priorities (7.14.2.1).
const (
	EventPriorityDebug    EventPriority = 0
	EventPriorityInfo     EventPriority = 1
	EventPriorityCritical EventPriority = 2
)

// String returns the name of the priority.
func (p EventPriority) String() string {
	switch p {
	case EventPriorityDebug:
		return "debug"
	case EventPriorityInfo:
		return "info"
	case EventPriorityCritical:
		return "critical"
	default:
		return fmt.Sprintf("EventPriority(%d)", uint8(p))
	}
}

// EventTimestampType tells what an event's timestamp counts from
// (7.14.2.4, 7.14.2.5).
type EventTimestampType uint8

const (
	// EventTimestampEpoch counts milliseconds since the Unix epoch.
	EventTimestampEpoch EventTimestampType = iota
	// EventTimestampSystem counts milliseconds since the node booted.
	EventTimestampSystem
)

// EventRequestPath names the events a Read or a Subscribe asks for
// (10.6.8. EventPathIB). A nil field is a wildcard. IsUrgent asks a
// subscription to report the events at once, without waiting for its
// MinIntervalFloor.
type EventRequestPath struct {
	Endpoint *EndpointID
	Cluster  *ClusterID
	Event    *EventID
	IsUrgent bool
}

// NewEventRequestPath returns the path of one event.
func NewEventRequestPath(endpoint EndpointID, cluster ClusterID, event EventID) EventRequestPath {
	return EventRequestPath{Endpoint: &endpoint, Cluster: &cluster, Event: &event, IsUrgent: false}
}

// EventPath is the concrete path of a reported event.
type EventPath struct {
	Endpoint EndpointID
	Cluster  ClusterID
	Event    EventID
}

// EventReport is one event, or the status of an event path, in a report
// (10.6.9. EventReportIB).
type EventReport struct {
	Path EventPath
	// EventNumber orders the events of a node (7.14.2.2).
	EventNumber uint64
	Priority    EventPriority
	// Timestamp is in milliseconds since what TimestampType tells; a delta
	// timestamp is resolved against the event before it in the report.
	Timestamp     uint64
	TimestampType EventTimestampType
	// Data holds the event's fields; nil when Status is set.
	Data *AttributeValue
	// Status is the reason the event path is not reported; nil for an
	// event.
	Status *InvokeStatus
}

// Time returns the event's time when its timestamp is an epoch one.
func (e *EventReport) Time() (time.Time, bool) {
	if e.TimestampType != EventTimestampEpoch || e.Status != nil {
		return time.Time{}, false
	}
	return time.UnixMilli(int64(e.Timestamp)), true // nolint: gosec // milliseconds since 1970 fit
}

// EventDataIB field tags (10.6.10).
const (
	tagEventDataPath                 = 0
	tagEventDataEventNumber          = 1
	tagEventDataPriority             = 2
	tagEventDataEpochTimestamp       = 3
	tagEventDataSystemTimestamp      = 4
	tagEventDataDeltaEpochTimestamp  = 5
	tagEventDataDeltaSystemTimestamp = 6
	tagEventDataData                 = 7
)

// encodeEventRequests encodes the EventRequests of a Read or a Subscribe:
// an array of EventPathIB (10.6.8).
func encodeEventRequests(enc tlv.Encoder, tag tlv.Tag, paths []EventRequestPath) error {
	enc.BeginArray(tag)
	for _, p := range paths {
		enc.BeginList(tlv.NewAnonymousTag())
		if p.Endpoint != nil {
			enc.PutUnsigned2(tlv.NewContextTag(1), uint16(*p.Endpoint))
		}
		if p.Cluster != nil {
			if err := enc.PutUnsigned(tlv.NewContextTag(2), uint64(*p.Cluster)); err != nil {
				return err
			}
		}
		if p.Event != nil {
			if err := enc.PutUnsigned(tlv.NewContextTag(3), uint64(*p.Event)); err != nil {
				return err
			}
		}
		if p.IsUrgent {
			enc.PutBool(tlv.NewContextTag(4), true)
		}
		if err := enc.EndContainer(); err != nil {
			return err
		}
	}
	return enc.EndContainer()
}

// encodeEventFilters encodes EventFilters asking for the events numbered
// eventMin and up: an array of one EventFilterIB (10.6.6).
func encodeEventFilters(enc tlv.Encoder, tag tlv.Tag, eventMin uint64) error {
	enc.BeginArray(tag)
	enc.BeginStructure(tlv.NewAnonymousTag())
	enc.PutUnsigned8(tlv.NewContextTag(1), eventMin)
	if err := enc.EndContainer(); err != nil {
		return err
	}
	return enc.EndContainer()
}

// eventTimeline resolves the delta timestamps of the events of a report
// against the event before each (10.6.10).
type eventTimeline struct {
	last     uint64
	lastType EventTimestampType
	have     bool
}

// decodeEventReportIB decodes an EventReportIB (10.6.9).
func decodeEventReportIB(r *AttributeValue, timeline *eventTimeline) (EventReport, error) {
	var e EventReport
	if !r.Element.Type().IsStructure() {
		return e, errors.New("EventReportIB is not a structure")
	}
	statusIB, dataIB := valueField(r, 0), valueField(r, 1)
	if (statusIB == nil) == (dataIB == nil) {
		return e, errors.New("EventReportIB has neither or both of status and data")
	}
	if statusIB != nil {
		if !statusIB.Element.Type().IsStructure() {
			return e, errors.New("EventStatusIB is not a structure")
		}
		path, err := decodeEventPath(valueField(statusIB, 0))
		if err != nil {
			return e, err
		}
		status, err := valueStatus(valueField(statusIB, 1))
		if err != nil {
			return e, err
		}
		e.Path, e.Status = path, status
		return e, nil
	}
	if !dataIB.Element.Type().IsStructure() {
		return e, errors.New("EventDataIB is not a structure")
	}
	path, err := decodeEventPath(valueField(dataIB, tagEventDataPath))
	if err != nil {
		return e, err
	}
	e.Path = path
	if e.EventNumber, err = valueUnsigned(valueField(dataIB, tagEventDataEventNumber), 1<<64-1); err != nil {
		return e, fmt.Errorf("EventNumber: %w", err)
	}
	priority, err := valueUnsigned(valueField(dataIB, tagEventDataPriority), uint64(EventPriorityCritical))
	if err != nil {
		return e, fmt.Errorf("Priority: %w", err)
	}
	e.Priority = EventPriority(priority)
	if err := resolveEventTimestamp(dataIB, &e, timeline); err != nil {
		return e, err
	}
	e.Data = valueField(dataIB, tagEventDataData)
	return e, nil
}

// resolveEventTimestamp takes the one timestamp of an EventDataIB,
// resolving a delta one.
func resolveEventTimestamp(dataIB *AttributeValue, e *EventReport, timeline *eventTimeline) error {
	type field struct {
		tag   uint8
		typ   EventTimestampType
		delta bool
	}
	found := 0
	for _, f := range []field{
		{tagEventDataEpochTimestamp, EventTimestampEpoch, false},
		{tagEventDataSystemTimestamp, EventTimestampSystem, false},
		{tagEventDataDeltaEpochTimestamp, EventTimestampEpoch, true},
		{tagEventDataDeltaSystemTimestamp, EventTimestampSystem, true},
	} {
		v := valueField(dataIB, f.tag)
		if v == nil {
			continue
		}
		found++
		n, err := valueUnsigned(v, 1<<64-1)
		if err != nil {
			return fmt.Errorf("timestamp: %w", err)
		}
		if f.delta {
			if !timeline.have || timeline.lastType != f.typ {
				return errors.New("a delta timestamp follows no event of its kind")
			}
			n += timeline.last
		}
		e.Timestamp, e.TimestampType = n, f.typ
	}
	if found != 1 {
		return fmt.Errorf("EventDataIB has %d timestamps, want 1", found)
	}
	timeline.last, timeline.lastType, timeline.have = e.Timestamp, e.TimestampType, true
	return nil
}

// decodeEventPath decodes the concrete EventPathIB of a report (10.6.8).
func decodeEventPath(v *AttributeValue) (EventPath, error) {
	var p EventPath
	if v == nil || !v.Element.Type().IsList() {
		return p, errors.New("missing EventPathIB")
	}
	ep, err := valueUnsigned(valueField(v, 1), 0xFFFF)
	if err != nil {
		return p, fmt.Errorf("EventPathIB endpoint: %w", err)
	}
	cl, err := valueUnsigned(valueField(v, 2), 0xFFFFFFFF)
	if err != nil {
		return p, fmt.Errorf("EventPathIB cluster: %w", err)
	}
	ev, err := valueUnsigned(valueField(v, 3), 0xFFFFFFFF)
	if err != nil {
		return p, fmt.Errorf("EventPathIB event: %w", err)
	}
	return EventPath{Endpoint: EndpointID(ep), Cluster: ClusterID(cl), Event: EventID(ev)}, nil
}
