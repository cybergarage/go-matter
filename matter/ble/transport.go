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
	"fmt"

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
	//
	// The write must also happen *before* subscribing to C2, not after:
	// some commissions only flush their buffered handshake response once
	// they observe the client enabling notifications following the write,
	// and never deliver it if notifications were already enabled beforehand
	// (confirmed by comparing raw HCI captures of a working chip-tool
	// session, which writes C1 then enables C2, against go-matter's
	// previous subscribe-then-write order, which the same device never
	// responded to).
	//
	// Not every commissionee's C1 characteristic actually advertises the
	// GATT "Write" (with-response) property, though: on one real device
	// (VendorID 5010, ProductID 259), go-ble's underlying CoreBluetooth
	// binding rejected the with-response write outright — "the specified
	// UUID is not allowed for this operation" — a client-side property
	// check that fires before anything is transmitted to the peer, not a
	// peer-side NAK. So falling back to a without-response write here is
	// always safe: the with-response attempt above never reached the
	// device.
	handshakeReq := btp.NewHandshakeRequest().Bytes()
	if _, withRespErr := t.Write(ctx, handshakeReq); withRespErr != nil {
		if _, withoutRespErr := t.WriteWithoutResponse(ctx, handshakeReq); withoutRespErr != nil {
			return nil, fmt.Errorf("write C1 handshake request: with response: %w; without response: %w", withRespErr, withoutRespErr)
		}
	}

	if err := t.Subscribe(); err != nil {
		return nil, fmt.Errorf("subscribe to C2 notifications: %w", err)
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
