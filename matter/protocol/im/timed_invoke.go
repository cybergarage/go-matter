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
	"fmt"
	"time"

	"github.com/cybergarage/go-matter/matter/encoding/message"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
)

// DefaultTimedInteractionTimeout is how long TimedInvoke gives the peer to
// receive the invoke after the TimedRequest, when the caller gives none.
const DefaultTimedInteractionTimeout = 10 * time.Second

// TimedInvoke invokes a command in a timed interaction (Matter Core
// 8.7.2), as a command which requires one must be: it sends a
// TimedRequest with timeout on a new exchange and, once the peer accepts
// it, the InvokeRequest with timed-request set on the same exchange. A
// peer which refuses the TimedRequest is reported as the response's
// status.
func TimedInvoke(sess SecureSession, endpointID EndpointID, clusterID ClusterID, commandID CommandID, commandFields []byte, timeout time.Duration) (*InvokeResponse, error) {
	if timeout <= 0 {
		timeout = DefaultTimedInteractionTimeout
	}
	millis := min(0xFFFF, timeout.Milliseconds())
	exchangeID := message.NewFirstExchangeID()

	// TimedRequestMessage (10.7.8).
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	enc.PutUnsigned2(tlv.NewContextTag(0), uint16(millis))
	enc.PutUnsigned1(tlv.NewContextTag(interactionModelRevisionTag), interactionModelRevision)
	if err := enc.EndContainer(); err != nil {
		return nil, err
	}
	if err := transmitOnExchange(sess, message.TimedRequestMessage, exchangeID, enc.Bytes()); err != nil {
		return nil, fmt.Errorf("im: transmit TimedRequest: %w", err)
	}
	raw, err := receiveExchangeResponse(sess, exchangeID)
	if err != nil {
		return nil, fmt.Errorf("im: receive the TimedRequest's StatusResponse: %w", err)
	}
	accepted, err := parseInvokeResponse(raw)
	if err != nil {
		return nil, err
	}
	if !accepted.IsSuccess() {
		return accepted, nil
	}

	payload, err := buildInvokeRequestPayloadTimed(endpointID, clusterID, commandID, commandFields, true)
	if err != nil {
		return nil, fmt.Errorf("im: build InvokeRequest payload: %w", err)
	}
	if err := transmitOnExchange(sess, message.InvokeRequestMessage, exchangeID, payload); err != nil {
		return nil, fmt.Errorf("im: transmit InvokeRequest: %w", err)
	}
	raw, err = receiveExchangeResponse(sess, exchangeID)
	if err != nil {
		return nil, fmt.Errorf("im: receive InvokeResponse: %w", err)
	}
	return parseInvokeResponse(raw)
}

func transmitOnExchange(sess SecureSession, opcode message.Opcode, exchangeID message.ExchangeID, payload []byte) error {
	hdr, err := buildIMProtocolHeaderOnExchange(opcode, exchangeID)
	if err != nil {
		return err
	}
	return sess.Transmit(append(hdr, payload...))
}
