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
	"sync/atomic"
	"testing"
	"time"

	"github.com/cybergarage/go-matter/matter/encoding/message"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
)

func buildSubscribeRequest(minFloor, maxCeil uint16, endpoint EndpointID, cluster ClusterID) []byte {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	enc.PutBool(tlv.NewContextTag(0), false)
	enc.PutUnsigned2(tlv.NewContextTag(1), minFloor)
	enc.PutUnsigned2(tlv.NewContextTag(2), maxCeil)
	enc.BeginArray(tlv.NewContextTag(3))
	enc.BeginList(tlv.NewAnonymousTag())
	enc.PutUnsigned2(tlv.NewContextTag(2), uint16(endpoint))
	_ = enc.PutUnsigned(tlv.NewContextTag(3), uint64(cluster))
	_ = enc.EndContainer()
	_ = enc.EndContainer()
	enc.PutBool(tlv.NewContextTag(7), false)
	enc.PutUnsigned1(tlv.NewContextTag(interactionModelRevisionTag), interactionModelRevision)
	_ = enc.EndContainer()
	return enc.Bytes()
}

func buildStatusResponse(status Status) []byte {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	enc.PutUnsigned1(tlv.NewContextTag(0), uint8(status))
	enc.PutUnsigned1(tlv.NewContextTag(interactionModelRevisionTag), interactionModelRevision)
	_ = enc.EndContainer()
	return enc.Bytes()
}

// receivedReport is a ReportData's subscription ID and its attribute
// values by path.
type receivedReport struct {
	exchange       message.ExchangeID
	initiator      bool
	subscriptionID uint32
	values         map[AttributePath]tlv.Element
}

func receiveIM(t *testing.T, client SecureSession, opcode message.Opcode) (message.ProtocolHeader, []byte) {
	t.Helper()
	type result struct {
		raw []byte
		err error
	}
	ch := make(chan result, 1)
	go func() {
		raw, err := client.Receive()
		ch <- result{raw, err}
	}()
	var r result
	select {
	case r = <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("no message 0x%02X arrived", uint8(opcode))
	}
	if r.err != nil {
		t.Fatal(r.err)
	}
	hdr, err := message.NewProtocolHeaderFromBytes(r.raw)
	if err != nil {
		t.Fatal(err)
	}
	if hdr.Opcode() != opcode {
		t.Fatalf("received opcode 0x%02X, want 0x%02X", uint8(hdr.Opcode()), uint8(opcode))
	}
	hdrBytes, _ := hdr.Bytes()
	return hdr, r.raw[len(hdrBytes):]
}

func receiveReport(t *testing.T, client SecureSession) receivedReport {
	t.Helper()
	hdr, body := receiveIM(t, client, message.ReportDataMessage)
	report := receivedReport{
		exchange:  hdr.ExchangeID(),
		initiator: hdr.IsInitiator(),
		values:    map[AttributePath]tlv.Element{},
	}
	dec, err := openTopLevel(body)
	if err != nil {
		t.Fatal(err)
	}
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			break
		}
		tag, _ := contextNumber(elem)
		switch {
		case tag == 0 && !elem.Type().IsContainer():
			v, _ := elem.Unsigned()
			report.subscriptionID = uint32(v)
		case tag == 1 && elem.Type().IsArray():
			for dec.Next() {
				ib := dec.Element()
				if ib.Type().IsEndOfContainer() {
					break
				}
				var path AttributePath
				var value tlv.Element
				walkReportIB(t, dec, &path, &value)
				if value != nil {
					report.values[path] = value
				}
			}
		case elem.Type().IsContainer():
			if err := skipContainer(dec); err != nil {
				t.Fatal(err)
			}
		}
	}
	return report
}

// walkReportIB reads an AttributeReportIB, keeping the path and data of
// its AttributeDataIB.
func walkReportIB(t *testing.T, dec tlv.Decoder, path *AttributePath, value *tlv.Element) {
	t.Helper()
	depth := 1
	var inPath bool
	for depth > 0 && dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			depth--
			inPath = false
			continue
		}
		tag, _ := contextNumber(elem)
		if elem.Type().IsContainer() {
			depth++
			inPath = tag == 1 && elem.Type().IsList()
			if tag == 2 && depth == 3 {
				*value = elem
				if err := skipContainer(dec); err != nil {
					t.Fatal(err)
				}
				depth--
			}
			continue
		}
		switch {
		case inPath && tag == 2:
			v, _ := elem.Unsigned()
			path.Endpoint = EndpointID(v)
		case inPath && tag == 3:
			v, _ := elem.Unsigned()
			path.Cluster = ClusterID(v)
		case inPath && tag == 4:
			v, _ := elem.Unsigned()
			path.Attribute = AttributeID(v)
		case !inPath && tag == 2 && depth == 2:
			*value = elem
		}
	}
}

func TestServerSubscribe(t *testing.T) {
	srv := testServer()
	var on atomic.Bool
	srv.HandleAttribute(1, 0x0006, 0x0000, func(enc tlv.Encoder, tag tlv.Tag) Status {
		enc.PutBool(tag, on.Load())
		return StatusSuccess
	})
	srv.HandleAttribute(1, 0x0006, 0x4000, func(enc tlv.Encoder, tag tlv.Tag) Status {
		enc.PutBool(tag, true)
		return StatusSuccess
	})
	client := startServer(t, srv)

	exchange := message.NewFirstExchangeID()
	if err := transmitOnExchange(client, message.SubscribeRequestMessage, exchange, buildSubscribeRequest(0, 2, 1, 0x0006)); err != nil {
		t.Fatal(err)
	}
	priming := receiveReport(t, client)
	if priming.subscriptionID == 0 || priming.exchange != exchange {
		t.Fatalf("priming report: subscription %d on exchange %d, want an ID on exchange %d", priming.subscriptionID, priming.exchange, exchange)
	}
	onOff := AttributePath{Endpoint: 1, Cluster: 0x0006, Attribute: 0x0000}
	if v, ok := priming.values[onOff]; !ok {
		t.Fatalf("the priming report lacks OnOff: %v", priming.values)
	} else if b, _ := v.Bool(); b {
		t.Fatal("the priming report has OnOff true, want false")
	}
	if _, ok := priming.values[AttributePath{Endpoint: 1, Cluster: 0x0006, Attribute: 0x4000}]; !ok {
		t.Fatal("the priming report lacks GlobalSceneControl")
	}

	if err := transmitOnExchange(client, message.StatusResponseMessage, exchange, buildStatusResponse(StatusSuccess)); err != nil {
		t.Fatal(err)
	}
	_, body := receiveIM(t, client, message.SubscribeResponseMessage)
	dec, err := openTopLevel(body)
	if err != nil {
		t.Fatal(err)
	}
	var gotID, gotMax uint64
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			break
		}
		switch tag, _ := contextNumber(elem); tag {
		case 0:
			gotID, _ = elem.Unsigned()
		case 2:
			gotMax, _ = elem.Unsigned()
		}
	}
	if uint32(gotID) != priming.subscriptionID || gotMax != 2 {
		t.Fatalf("SubscribeResponse = (id %d, max %d), want (%d, 2)", gotID, gotMax, priming.subscriptionID)
	}

	on.Store(true)
	srv.NotifyAttributeChanged(onOff)
	srv.NotifyAttributeChanged(AttributePath{Endpoint: 2, Cluster: 0x0006, Attribute: 0x0000})
	change := receiveReport(t, client)
	if change.subscriptionID != priming.subscriptionID || !change.initiator {
		t.Fatalf("change report: subscription %d initiator %v", change.subscriptionID, change.initiator)
	}
	if len(change.values) != 1 {
		t.Fatalf("change report has %v, want only OnOff", change.values)
	}
	if b, _ := change.values[onOff].Bool(); !b {
		t.Fatal("the change report has OnOff false, want true")
	}
	if err := sendIMResponse(client, change.exchange, message.StatusResponseMessage, buildStatusResponse(StatusSuccess)); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	keepAlive := receiveReport(t, client)
	if keepAlive.subscriptionID != priming.subscriptionID || len(keepAlive.values) != 0 {
		t.Fatalf("keep-alive report: subscription %d with %v", keepAlive.subscriptionID, keepAlive.values)
	}
	if elapsed := time.Since(start); elapsed < time.Second {
		t.Fatalf("the keep-alive came after %v, want about the 2s max interval", elapsed)
	}

	srv.EndSession(srv.subs.onlySession(t))
}

func (subs *subscriptions) onlySession(t *testing.T) SecureSession {
	t.Helper()
	subs.mutex.Lock()
	defer subs.mutex.Unlock()
	if len(subs.active) != 1 {
		t.Fatalf("%d active subscriptions, want 1", len(subs.active))
	}
	for _, sub := range subs.active {
		return sub.sess
	}
	return nil
}
