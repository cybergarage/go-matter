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
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter/encoding/message"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
)

// Subscription defaults.
const (
	// DefaultSubscribeMaxInterval is the MaxIntervalCeiling a subscription
	// asks for unless WithMaxInterval sets another.
	DefaultSubscribeMaxInterval = 60 * time.Second
	// DefaultLivenessMargin is how long past the subscription's MaxInterval
	// a report may be late before the subscription is taken for lost: the
	// publisher's retransmissions may delay it.
	DefaultLivenessMargin = 30 * time.Second
	// maxResubscribeBackoff bounds the wait between resubscribe attempts.
	maxResubscribeBackoff = time.Minute
)

var (
	// ErrSubscriptionLost is reported when no report arrived within the
	// subscription's MaxInterval and the liveness margin.
	ErrSubscriptionLost = errors.New("im: subscription lost: no report within its max interval")
	// ErrSubscriptionClosed is returned by a Subscription after Close.
	ErrSubscriptionClosed = errors.New("im: subscription closed")
)

// AttributeRequestPath names the attributes a Subscribe asks for
// (10.6.2. AttributePathIB). A nil field is a wildcard.
type AttributeRequestPath struct {
	Endpoint  *EndpointID
	Cluster   *ClusterID
	Attribute *AttributeID
}

// NewAttributeRequestPath returns the path of one attribute.
func NewAttributeRequestPath(endpoint EndpointID, cluster ClusterID, attribute AttributeID) AttributeRequestPath {
	return AttributeRequestPath{Endpoint: &endpoint, Cluster: &cluster, Attribute: &attribute}
}

// AttributeReport is the value, or the status, of one attribute in a
// report (10.6.4. AttributeReportIB).
type AttributeReport struct {
	Path AttributePath
	// DataVersion is the cluster's data version; HasDataVersion is false
	// when the report has none.
	DataVersion    uint32
	HasDataVersion bool
	// Value is the attribute's value; nil when Status is set.
	Value *AttributeValue
	// Status is the reason the attribute is not reported; nil when Value
	// is set.
	Status *InvokeStatus
}

// Report is what a subscription reports at once: the attributes of a
// ReportData, its chunks joined (10.7.3).
type Report struct {
	SubscriptionID uint32
	// Priming is true for the first report of a subscription, which holds
	// every subscribed attribute, and of a resubscription.
	Priming    bool
	Attributes []AttributeReport
}

// ReportHandler receives the reports of a subscription, one at a time and
// in order. It may use the session, such as to read or invoke, but should
// return promptly: the reports which follow wait for it.
type ReportHandler func(*Report)

// SubscribeOption configures a subscription.
type SubscribeOption func(*subscribeConfig)

type subscribeConfig struct {
	minInterval       time.Duration
	maxInterval       time.Duration
	keepSubscriptions bool
	fabricFiltered    bool
	resubscribe       bool
	livenessMargin    time.Duration
	onError           func(error)
}

// WithMinInterval sets MinIntervalFloor, the least time between two
// reports, in whole seconds. Defaults to 0.
func WithMinInterval(d time.Duration) SubscribeOption {
	return func(c *subscribeConfig) {
		c.minInterval = d
	}
}

// WithMaxInterval sets MaxIntervalCeiling, the most time the publisher may
// let pass without a report, in whole seconds; it may choose less.
// Defaults to DefaultSubscribeMaxInterval.
func WithMaxInterval(d time.Duration) SubscribeOption {
	return func(c *subscribeConfig) {
		c.maxInterval = d
	}
}

// WithKeepSubscriptions sets KeepSubscriptions: when false, the publisher
// ends the other subscriptions of this node on the session. Defaults to
// true.
func WithKeepSubscriptions(keep bool) SubscribeOption {
	return func(c *subscribeConfig) {
		c.keepSubscriptions = keep
	}
}

// WithFabricFiltered sets IsFabricFiltered, which limits fabric-scoped
// lists to this node's fabric. Defaults to true.
func WithFabricFiltered(filtered bool) SubscribeOption {
	return func(c *subscribeConfig) {
		c.fabricFiltered = filtered
	}
}

// WithResubscribe sets whether a lost subscription subscribes again on the
// same session, with a backoff, until it succeeds or the subscription is
// closed. Defaults to true. A failed session ends the subscription
// whichever way.
func WithResubscribe(resubscribe bool) SubscribeOption {
	return func(c *subscribeConfig) {
		c.resubscribe = resubscribe
	}
}

// WithLivenessMargin sets how long past its MaxInterval a report may be
// late. Defaults to DefaultLivenessMargin.
func WithLivenessMargin(d time.Duration) SubscribeOption {
	return func(c *subscribeConfig) {
		c.livenessMargin = d
	}
}

// WithSubscribeErrorHandler sets a function told when the subscription is
// lost, when an attempt to subscribe again fails, and when the
// subscription ends with an error. It is not called after Close.
func WithSubscribeErrorHandler(f func(error)) SubscribeOption {
	return func(c *subscribeConfig) {
		c.onError = f
	}
}

// Subscription is an active subscription (8.5. Subscribe Interaction).
type Subscription struct {
	mux     *ExchangeMux
	paths   []AttributeRequestPath
	cfg     subscribeConfig
	handler ReportHandler

	mutex       sync.Mutex
	id          uint32
	maxInterval time.Duration
	chunks      map[message.ExchangeID]*Report
	reports     []*Report
	wake        chan struct{}
	alive       chan struct{}
	err         error
	ended       bool
	done        chan struct{}
}

// Subscribe subscribes to the attributes of paths and returns once the
// publisher has sent their values, which the handler receives as the
// priming report, and accepted the subscription. ctx bounds the subscribe
// only. Reports arrive until Close, or until the subscription ends with an
// error, after which Done is closed.
func (m *ExchangeMux) Subscribe(ctx context.Context, paths []AttributeRequestPath, handler ReportHandler, opts ...SubscribeOption) (*Subscription, error) {
	if len(paths) == 0 {
		return nil, errors.New("im: Subscribe: no attribute path")
	}
	if handler == nil {
		return nil, errors.New("im: Subscribe: no report handler")
	}
	cfg := subscribeConfig{
		minInterval:       0,
		maxInterval:       DefaultSubscribeMaxInterval,
		keepSubscriptions: true,
		fabricFiltered:    true,
		resubscribe:       true,
		livenessMargin:    DefaultLivenessMargin,
		onError:           nil,
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	// The intervals go on the wire in whole seconds (10.7.2).
	if cfg.minInterval < 0 || cfg.maxInterval < cfg.minInterval || cfg.maxInterval > 0xFFFF*time.Second ||
		cfg.minInterval%time.Second != 0 || cfg.maxInterval%time.Second != 0 {
		return nil, fmt.Errorf("im: Subscribe: intervals %v to %v are not whole seconds from 0 to 65535 in order", cfg.minInterval, cfg.maxInterval)
	}
	if cfg.livenessMargin < 0 {
		return nil, fmt.Errorf("im: Subscribe: negative liveness margin %v", cfg.livenessMargin)
	}
	sub := &Subscription{
		mux:         m,
		paths:       append([]AttributeRequestPath(nil), paths...),
		cfg:         cfg,
		handler:     handler,
		mutex:       sync.Mutex{},
		id:          0,
		maxInterval: 0,
		chunks:      map[message.ExchangeID]*Report{},
		reports:     nil,
		wake:        make(chan struct{}, 1),
		alive:       make(chan struct{}, 1),
		err:         nil,
		ended:       false,
		done:        make(chan struct{}),
	}
	priming, err := sub.subscribe(ctx)
	if err != nil {
		return nil, err
	}
	sub.enqueue(priming)
	go sub.deliver()
	go sub.watch()
	return sub, nil
}

// ID returns the subscription ID the publisher assigned; it changes when
// the subscription subscribes again.
func (sub *Subscription) ID() uint32 {
	sub.mutex.Lock()
	defer sub.mutex.Unlock()
	return sub.id
}

// MaxInterval returns the interval the publisher chose, within which it
// reports at least once.
func (sub *Subscription) MaxInterval() time.Duration {
	sub.mutex.Lock()
	defer sub.mutex.Unlock()
	return sub.maxInterval
}

// Done is closed when the subscription ends.
func (sub *Subscription) Done() <-chan struct{} {
	return sub.done
}

// Err returns why the subscription ended: ErrSubscriptionClosed after
// Close, nil while it is active.
func (sub *Subscription) Err() error {
	sub.mutex.Lock()
	defer sub.mutex.Unlock()
	return sub.err
}

// Close ends the subscription. The publisher learns it with the next
// report, which is answered with InvalidSubscription (8.5.2).
func (sub *Subscription) Close() error {
	sub.end(nil)
	return nil
}

// subscribe runs a Subscribe interaction (8.5.1) and returns its priming
// report: the publisher reports the subscribed attributes, in chunks, each
// answered with a StatusResponse, then sends a SubscribeResponse.
func (sub *Subscription) subscribe(ctx context.Context) (_ *Report, err error) {
	var id uint32
	registered := false
	defer func() {
		// A failed (re)subscription leaves no ID registered.
		if err != nil && registered {
			sub.mux.unregister(id, sub)
		}
	}()
	payload, err := encodeSubscribeRequest(sub.paths, sub.cfg)
	if err != nil {
		return nil, fmt.Errorf("im: build SubscribeRequest: %w", err)
	}
	exchange := sub.mux.NewExchangeID()
	if err := transmitOnExchange(sub.mux, message.SubscribeRequestMessage, exchange, payload); err != nil {
		return nil, fmt.Errorf("im: transmit SubscribeRequest: %w", err)
	}
	priming := &Report{SubscriptionID: 0, Priming: true, Attributes: nil}
	for {
		raw, err := sub.mux.ReceiveExchangeContext(ctx, exchange)
		if err != nil {
			return nil, fmt.Errorf("im: Subscribe: %w", err)
		}
		hdr, err := message.NewProtocolHeaderFromBytes(raw)
		if err != nil {
			return nil, fmt.Errorf("im: Subscribe: %w", err)
		}
		body, err := messageBody(raw, hdr)
		if err != nil {
			return nil, fmt.Errorf("im: Subscribe: %w", err)
		}
		switch {
		case hdr.Opcode().IsStatusResponseMessage():
			status, err := parseStatusResponseMessage(body)
			if err != nil {
				return nil, fmt.Errorf("im: Subscribe: %w", err)
			}
			return nil, fmt.Errorf("im: Subscribe: refused with status 0x%02X", status.IMStatus)
		case hdr.Opcode().IsReportDataMessage():
			rd, err := decodeReportData(raw)
			if err != nil {
				return nil, err
			}
			if !rd.hasSubscriptionID || (registered && rd.subscriptionID != id) {
				return nil, errors.New("im: Subscribe: the priming report has no or another subscription ID")
			}
			if !registered {
				id = rd.subscriptionID
				// Registered before the priming is answered, so no report
				// of the new subscription can come unknown.
				if err := sub.mux.register(id, sub); err != nil {
					return nil, err
				}
				registered = true
			}
			priming.SubscriptionID = id
			if priming.Attributes, err = mergeAttributeReports(priming.Attributes, rd.attributes); err != nil {
				return nil, fmt.Errorf("im: Subscribe: priming report: %w", err)
			}
			if err := transmitOnExchange(sub.mux, message.StatusResponseMessage, exchange, statusResponsePayload(StatusSuccess)); err != nil {
				return nil, fmt.Errorf("im: Subscribe: answer the priming report: %w", err)
			}
		case hdr.Opcode() == message.SubscribeResponseMessage:
			respID, maxInterval, err := decodeSubscribeResponse(body)
			if err != nil {
				return nil, err
			}
			if !registered || respID != id {
				return nil, errors.New("im: Subscribe: the SubscribeResponse is not for the primed subscription")
			}
			sub.setID(id, maxInterval)
			return priming, nil
		default:
			log.Debugf("im: Subscribe: skip opcode %v", hdr.Opcode())
		}
	}
}

func (sub *Subscription) setID(id uint32, maxInterval time.Duration) {
	sub.mutex.Lock()
	defer sub.mutex.Unlock()
	sub.id = id
	sub.maxInterval = maxInterval
}

// received takes a chunk of a report the publisher sent on its exchange.
func (sub *Subscription) received(exchange message.ExchangeID, rd *reportData) {
	select {
	case sub.alive <- struct{}{}:
	default:
	}
	sub.mutex.Lock()
	report := sub.chunks[exchange]
	if report == nil {
		report = &Report{SubscriptionID: rd.subscriptionID, Priming: false, Attributes: nil}
	}
	var err error
	if report.Attributes, err = mergeAttributeReports(report.Attributes, rd.attributes); err != nil {
		// A malformed report is dropped whole, its earlier chunks too.
		delete(sub.chunks, exchange)
		sub.mutex.Unlock()
		sub.reportError(fmt.Errorf("im: subscription %d: drop a report: %w", rd.subscriptionID, err))
		return
	}
	if rd.moreChunks {
		sub.chunks[exchange] = report
		sub.mutex.Unlock()
		return
	}
	delete(sub.chunks, exchange)
	sub.mutex.Unlock()
	// An empty report only keeps the subscription alive.
	if 0 < len(report.Attributes) {
		sub.enqueue(report)
	}
}

func (sub *Subscription) enqueue(report *Report) {
	sub.mutex.Lock()
	sub.reports = append(sub.reports, report)
	sub.mutex.Unlock()
	select {
	case sub.wake <- struct{}{}:
	default:
	}
}

// deliver calls the handler with the reports, in order.
func (sub *Subscription) deliver() {
	for {
		sub.mutex.Lock()
		if sub.ended {
			sub.mutex.Unlock()
			return
		}
		if len(sub.reports) == 0 {
			sub.mutex.Unlock()
			select {
			case <-sub.wake:
				continue
			case <-sub.done:
				return
			}
		}
		report := sub.reports[0]
		sub.reports = sub.reports[1:]
		sub.mutex.Unlock()
		sub.handler(report)
	}
}

// watch takes the subscription for lost when no report arrives within its
// MaxInterval and the liveness margin, and subscribes again (8.5.2).
func (sub *Subscription) watch() {
	for {
		timer := time.NewTimer(sub.MaxInterval() + sub.cfg.livenessMargin)
		select {
		case <-sub.done:
			timer.Stop()
			return
		case <-sub.alive:
			timer.Stop()
			continue
		case <-timer.C:
		}
		lost := fmt.Errorf("%w (subscription %d, max interval %v)", ErrSubscriptionLost, sub.ID(), sub.MaxInterval())
		if !sub.cfg.resubscribe {
			sub.end(lost)
			return
		}
		sub.reportError(lost)
		if !sub.resubscribe() {
			return
		}
	}
}

// resubscribe subscribes again with a growing backoff until it succeeds,
// the subscription is closed, or the session fails.
func (sub *Subscription) resubscribe() bool {
	backoff := time.Second
	for {
		select {
		case <-sub.done:
			return false
		case <-sub.mux.Done():
			sub.end(sub.mux.Err())
			return false
		default:
		}
		old := sub.ID()
		ctx, cancel := context.WithTimeout(context.Background(), 2*sub.mux.timeout)
		priming, err := sub.subscribe(ctx)
		cancel()
		if err == nil {
			sub.mux.unregister(old, sub)
			sub.mutex.Lock()
			ended := sub.ended
			sub.mutex.Unlock()
			if ended {
				sub.mux.unregister(sub.ID(), sub)
				return false
			}
			log.Infof("im: subscription %d resubscribed as %d", old, sub.ID())
			sub.enqueue(priming)
			return true
		}
		sub.reportError(fmt.Errorf("im: resubscribe: %w", err))
		wait := backoff + rand.N(backoff/2+1) // nolint: gosec // jitter
		backoff = min(2*backoff, maxResubscribeBackoff)
		select {
		case <-sub.done:
			return false
		case <-sub.mux.Done():
			sub.end(sub.mux.Err())
			return false
		case <-time.After(wait):
		}
	}
}

func (sub *Subscription) reportError(err error) {
	if sub.cfg.onError != nil {
		sub.cfg.onError(err)
	}
}

// end ends the subscription, with err, or by Close when err is nil.
func (sub *Subscription) end(err error) {
	sub.mutex.Lock()
	if sub.ended {
		sub.mutex.Unlock()
		return
	}
	sub.ended = true
	if err == nil {
		sub.err = ErrSubscriptionClosed
	} else {
		sub.err = err
	}
	id := sub.id
	close(sub.done)
	sub.mutex.Unlock()
	sub.mux.unregister(id, sub)
	if err != nil {
		sub.reportError(err)
	}
}

// encodeSubscribeRequest encodes a SubscribeRequestMessage (10.7.2).
func encodeSubscribeRequest(paths []AttributeRequestPath, cfg subscribeConfig) ([]byte, error) {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	enc.PutBool(tlv.NewContextTag(0), cfg.keepSubscriptions)
	enc.PutUnsigned2(tlv.NewContextTag(1), uint16(cfg.minInterval/time.Second)) // nolint: gosec // bounded by Subscribe
	enc.PutUnsigned2(tlv.NewContextTag(2), uint16(cfg.maxInterval/time.Second)) // nolint: gosec // bounded by Subscribe
	enc.BeginArray(tlv.NewContextTag(3))                                        // AttributeRequests
	for _, p := range paths {
		enc.BeginList(tlv.NewAnonymousTag()) // AttributePathIB
		if p.Endpoint != nil {
			enc.PutUnsigned2(tlv.NewContextTag(2), uint16(*p.Endpoint))
		}
		if p.Cluster != nil {
			if err := enc.PutUnsigned(tlv.NewContextTag(3), uint64(*p.Cluster)); err != nil {
				return nil, err
			}
		}
		if p.Attribute != nil {
			if err := enc.PutUnsigned(tlv.NewContextTag(4), uint64(*p.Attribute)); err != nil {
				return nil, err
			}
		}
		if err := enc.EndContainer(); err != nil {
			return nil, err
		}
	}
	if err := enc.EndContainer(); err != nil {
		return nil, err
	}
	enc.PutBool(tlv.NewContextTag(7), cfg.fabricFiltered)
	enc.PutUnsigned1(tlv.NewContextTag(interactionModelRevisionTag), interactionModelRevision)
	if err := enc.EndContainer(); err != nil {
		return nil, err
	}
	return enc.Bytes(), nil
}

// decodeSubscribeResponse decodes a SubscribeResponseMessage (10.7.4).
func decodeSubscribeResponse(body []byte) (uint32, time.Duration, error) {
	dec := tlv.NewDecoderWithBytes(body)
	if !dec.Next() || !dec.Element().Type().IsStructure() {
		return 0, 0, errors.New("im: SubscribeResponse: expected a structure")
	}
	var id, maxInterval uint64
	var haveID, haveMax bool
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			break
		}
		ct, ok := elem.Tag().(tlv.ContextTag)
		if !ok {
			continue
		}
		switch ct.ContextNumber() {
		case 0:
			id, haveID = elem.Unsigned()
		case 2:
			maxInterval, haveMax = elem.Unsigned()
		default:
			if elem.Type().IsContainer() {
				if err := skipContainer(dec); err != nil {
					return 0, 0, err
				}
			}
		}
	}
	if err := dec.Error(); err != nil {
		return 0, 0, fmt.Errorf("im: SubscribeResponse: %w", err)
	}
	if !haveID || id > 0xFFFFFFFF || !haveMax || maxInterval > 0xFFFF {
		return 0, 0, errors.New("im: SubscribeResponse: missing SubscriptionId or MaxInterval")
	}
	return uint32(id), time.Duration(maxInterval) * time.Second, nil
}

func statusResponsePayload(status Status) []byte {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	enc.PutUnsigned1(tlv.NewContextTag(0), uint8(status))
	enc.PutUnsigned1(tlv.NewContextTag(interactionModelRevisionTag), interactionModelRevision)
	_ = enc.EndContainer()
	return enc.Bytes()
}

func messageBody(raw []byte, hdr message.ProtocolHeader) ([]byte, error) {
	hb, err := hdr.Bytes()
	if err != nil {
		return nil, err
	}
	if len(raw) < len(hb) {
		return nil, errors.New("im: incomplete protocol header")
	}
	return raw[len(hb):], nil
}

// reportData is a decoded ReportDataMessage (10.7.3).
type reportData struct {
	subscriptionID    uint32
	hasSubscriptionID bool
	attributes        []attributeReportEntry
	moreChunks        bool
	suppressResponse  bool
}

// attributeReportEntry is an AttributeReport and whether it appends an item
// to the list the previous report of the same path holds (ListIndex null).
type attributeReportEntry struct {
	AttributeReport
	appendItem bool
}

// decodeReportData decodes a ReportDataMessage with the limits of a value
// read.
func decodeReportData(raw []byte) (*reportData, error) {
	if len(raw) > MaxValueReadBytes {
		return nil, errors.New("im: ReportData: byte limit exceeded")
	}
	hdr, err := message.NewProtocolHeaderFromBytes(raw)
	if err != nil {
		return nil, err
	}
	body, err := messageBody(raw, hdr)
	if err != nil {
		return nil, err
	}
	dec := tlv.NewDecoderWithBytes(body)
	if !dec.Next() || !dec.Element().Type().IsStructure() {
		return nil, errors.New("im: ReportData: expected a structure")
	}
	count := 0
	root, err := readValueTree(dec, dec.Element(), 0, &count)
	if err != nil {
		return nil, fmt.Errorf("im: ReportData: %w", err)
	}
	rd := &reportData{}
	var ok bool
	if f := valueField(root, 0); f != nil {
		n, err := valueUnsigned(f, 0xFFFFFFFF)
		if err != nil {
			return nil, fmt.Errorf("im: ReportData: SubscriptionId: %w", err)
		}
		rd.subscriptionID, rd.hasSubscriptionID = uint32(n), true
	}
	if f := valueField(root, 3); f != nil {
		if rd.moreChunks, ok = f.Element.Bool(); !ok {
			return nil, errors.New("im: ReportData: MoreChunkedMessages is not a boolean")
		}
	}
	if f := valueField(root, 4); f != nil {
		if rd.suppressResponse, ok = f.Element.Bool(); !ok {
			return nil, errors.New("im: ReportData: SuppressResponse is not a boolean")
		}
	}
	reports := valueField(root, 1)
	if reports == nil {
		return rd, nil
	}
	if !reports.Element.Type().IsArray() && !reports.Element.Type().IsList() {
		return nil, errors.New("im: ReportData: AttributeReportIBs is not an array")
	}
	for _, r := range reports.Children {
		entry, err := decodeAttributeReportIB(r)
		if err != nil {
			return nil, fmt.Errorf("im: ReportData: %w", err)
		}
		rd.attributes = append(rd.attributes, entry)
	}
	return rd, nil
}

// decodeAttributeReportIB decodes an AttributeReportIB (10.6.4).
func decodeAttributeReportIB(r *AttributeValue) (attributeReportEntry, error) {
	var entry attributeReportEntry
	if !r.Element.Type().IsStructure() {
		return entry, errors.New("AttributeReportIB is not a structure")
	}
	statusIB, dataIB := valueField(r, 0), valueField(r, 1)
	if (statusIB == nil) == (dataIB == nil) {
		return entry, errors.New("AttributeReportIB has neither or both of status and data")
	}
	if statusIB != nil {
		path, _, err := decodeReportPath(valueField(statusIB, 0))
		if err != nil {
			return entry, err
		}
		status, err := valueStatus(valueField(statusIB, 1))
		if err != nil {
			return entry, err
		}
		entry.Path, entry.Status = path, status
		return entry, nil
	}
	path, appendItem, err := decodeReportPath(valueField(dataIB, 1))
	if err != nil {
		return entry, err
	}
	entry.Path, entry.appendItem = path, appendItem
	if f := valueField(dataIB, 0); f != nil {
		n, err := valueUnsigned(f, 0xFFFFFFFF)
		if err != nil {
			return entry, fmt.Errorf("DataVersion: %w", err)
		}
		entry.DataVersion, entry.HasDataVersion = uint32(n), true
	}
	entry.Value = valueField(dataIB, 2)
	if entry.Value == nil {
		return entry, errors.New("AttributeDataIB has no Data")
	}
	return entry, nil
}

// decodeReportPath decodes the concrete AttributePathIB of a report, and
// whether its ListIndex is null, which appends the Data to a list
// (10.6.2).
func decodeReportPath(v *AttributeValue) (AttributePath, bool, error) {
	var p AttributePath
	if v == nil || !v.Element.Type().IsList() {
		return p, false, errors.New("missing AttributePathIB")
	}
	ep, err := valueUnsigned(valueField(v, 2), 0xFFFF)
	if err != nil {
		return p, false, fmt.Errorf("AttributePathIB endpoint: %w", err)
	}
	cl, err := valueUnsigned(valueField(v, 3), 0xFFFFFFFF)
	if err != nil {
		return p, false, fmt.Errorf("AttributePathIB cluster: %w", err)
	}
	at, err := valueUnsigned(valueField(v, 4), 0xFFFFFFFF)
	if err != nil {
		return p, false, fmt.Errorf("AttributePathIB attribute: %w", err)
	}
	p = AttributePath{Endpoint: EndpointID(ep), Cluster: ClusterID(cl), Attribute: AttributeID(at)}
	if index := valueField(v, 5); index != nil {
		if !index.Element.Type().IsNull() {
			return p, false, errors.New("indexed list update unsupported")
		}
		return p, true, nil
	}
	return p, false, nil
}

// mergeAttributeReports adds the entries of a chunk to the reports of the
// chunks before it: an item appended to a list (ListIndex null) joins the
// list its path last reported in the same report, which must have the same
// DataVersion. An item which appends to no list is an error: a report
// replaces a changed list whole before it appends to it (10.6.4.3).
func mergeAttributeReports(reports []AttributeReport, entries []attributeReportEntry) ([]AttributeReport, error) {
	for _, e := range entries {
		if !e.appendItem {
			reports = append(reports, e.AttributeReport)
			continue
		}
		var list *AttributeReport
		for i := len(reports) - 1; 0 <= i; i-- {
			if reports[i].Path == e.Path {
				list = &reports[i]
				break
			}
		}
		if list == nil || list.Value == nil || (!list.Value.Element.Type().IsArray() && !list.Value.Element.Type().IsList()) {
			return nil, fmt.Errorf("an item for %v appends to no list", e.Path)
		}
		if list.HasDataVersion != e.HasDataVersion || list.DataVersion != e.DataVersion {
			return nil, fmt.Errorf("an item for %v has another DataVersion than its list", e.Path)
		}
		list.Value.Children = append(list.Value.Children, e.Value)
	}
	return reports, nil
}
