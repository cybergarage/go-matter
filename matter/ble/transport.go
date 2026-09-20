// Copyright (C) 2025 The go-matter Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ble

import (
	"context"

	"github.com/cybergarage/go-ble/ble"
	"github.com/cybergarage/go-matter/matter/ble/btp"
)

// Transport represents a BLE transport.
type Transport interface {
	ble.Transport
	// Handshake performs the handshake operation.
	Handshake(ctx context.Context) (btp.HandshakeResponse, error)
}

type transport struct {
	ble.Transport
}

func newTransport(bleTransport ble.Transport) Transport {
	return &transport{
		Transport: bleTransport,
	}
}

// Handshake performs the handshake operation.
func (t *transport) Handshake(ctx context.Context) (btp.HandshakeResponse, error) {
	// 4.19.4.3. Session Establishment
	//
	// The handshake request must be sent as a GATT Write Request (i.e. with
	// an ATT-level response), not Write Without Response: some commissionee
	// BLE stacks only trigger their BTP state machine off an acknowledged
	// write, matching the reference chip-tool implementation's
	// BluezConnection::SendWriteRequestImpl, which explicitly sets
	// type="request" for every C1 write.
	_, err := t.Write(ctx, btp.NewHandshakeRequest().Bytes())
	if err != nil {
		return nil, err
	}

	resBytes, err := t.Read(ctx)
	if err != nil {
		return nil, err
	}

	res, err := btp.NewHandshakeResponseFromBytes(resBytes)
	if err != nil {
		return nil, err
	}

	return res, nil
}
