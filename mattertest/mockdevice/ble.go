// Copyright (C) 2026 The go-matter Authors. All rights reserved.
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

// This file adds a second personality to the Device this package's im_server.go
// documents: instead of simulating one that is already network-connected
// (Device.Start, a loopback UDP socket), StartBLE/NewFakeBLECentral simulate
// a BLE peripheral, so a test can exercise matter/ble's real BLE-transport
// code (scanning, GATT characteristic lookup, the BTP handshake and
// data-segment framing) without a real Bluetooth adapter — the class of bug
// this project's BLE debugging found could not be caught any other way (see
// matter/ble/btp/segment.go and matter/ble/transport.go's Handshake for what
// those bugs were).

package mockdevice

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cybergarage/go-ble/ble"
	matterble "github.com/cybergarage/go-matter/matter/ble"
)

// blePeripheralFragmentSize is deliberately small (well under the 244-byte
// maximum BtpEngine::sMaxFragmentSize allows, see matter/ble/btp/segment.go)
// so that ordinary PASE/CASE messages — a few hundred bytes each — actually
// exercise multi-segment fragmentation and reassembly, not just the trivial
// single-fragment path a larger, more realistic size would take for most of
// them.
const blePeripheralFragmentSize = 48

// BLEHandshakeObserver reports the order NewFakeBLECentral's simulated
// peripheral actually saw between the C1 handshake write and Subscribe
// being called, for a test to assert on directly. See
// blePeripheralTransport.HandshakeOrderOK.
type BLEHandshakeObserver interface {
	HandshakeOrderOK(ctx context.Context) (bool, error)
}

// NewFakeBLECentral wires dev up to a simulated BLE peripheral and starts it
// (via Device.StartBLE), then returns a matter/ble.Central that only ever
// discovers and connects to that one simulated peripheral, for injection via
// matter.WithCommissionerCentral in place of a real Bluetooth adapter. The
// returned BLEHandshakeObserver lets a test confirm the peripheral actually
// saw the write-then-subscribe order matter/ble/transport.go's Handshake is
// supposed to produce.
func NewFakeBLECentral(dev *Device) (matterble.Central, BLEHandshakeObserver, error) {
	ch := newBLEChannel()
	peripheral := newBLEPeripheralTransport(ch)
	if err := dev.StartBLE(peripheral, peripheral.Close); err != nil {
		return nil, nil, err
	}
	central := newFakeBLECentral(ch, dev.Discriminator(), dev.VendorID(), dev.ProductID())
	return central, peripheral, nil
}

// bleChannel is the simulated GATT wire between a fake central's Transport
// and the peripheral simulation: C1 writes flow one way, C2
// notifications/indications flow the other, and Subscribe is signaled
// separately, since (per the real device this was debugged against) the
// peripheral only flushes its handshake response once it observes
// subscription happening — regardless of how long after the C1 write.
//
// It also records which of the first C1 write and the first Subscribe call
// actually happened first, for HandshakeOrderOK. That has to be recorded
// here, synchronously with the central-side calls themselves
// (recordFirstWrite/recordFirstSubscribe), rather than inferred from the
// order the peripheral side happens to observe them in over these channels:
// toPeripheral is buffered, so WriteWithoutResponse returns without
// blocking, and which of it or a subsequent Subscribe call the peripheral's
// goroutine gets scheduled in time to react to first is a scheduler race
// that has nothing to do with which one matter/ble/transport.go's Handshake
// actually issued first.
type bleChannel struct {
	toPeripheral chan []byte
	toCentral    chan []byte
	subscribed   chan struct{}
	subscribeOne sync.Once
	closed       chan struct{}
	closeOnce    sync.Once

	orderMu             sync.Mutex
	orderWriteSeen      bool
	orderSubscribeSeen  bool
	orderWriteFirst     bool
	orderDetermined     chan struct{}
	orderDeterminedOnce sync.Once
}

func newBLEChannel() *bleChannel {
	return &bleChannel{
		toPeripheral:    make(chan []byte, 16),
		toCentral:       make(chan []byte, 16),
		subscribed:      make(chan struct{}),
		closed:          make(chan struct{}),
		orderDetermined: make(chan struct{}),
	}
}

func (c *bleChannel) subscribe() {
	c.subscribeOne.Do(func() { close(c.subscribed) })
}

func (c *bleChannel) close() {
	c.closeOnce.Do(func() { close(c.closed) })
}

// recordFirstWrite/recordFirstSubscribe latch in whichever is called first;
// later calls (including the other one, once both have been seen) are
// no-ops.
func (c *bleChannel) recordFirstWrite() {
	c.orderMu.Lock()
	defer c.orderMu.Unlock()
	if c.orderWriteSeen {
		return
	}
	c.orderWriteSeen = true
	if !c.orderSubscribeSeen {
		c.orderWriteFirst = true
	}
	c.maybeFinalizeOrderLocked()
}

func (c *bleChannel) recordFirstSubscribe() {
	c.orderMu.Lock()
	defer c.orderMu.Unlock()
	if c.orderSubscribeSeen {
		return
	}
	c.orderSubscribeSeen = true
	if !c.orderWriteSeen {
		c.orderWriteFirst = false
	}
	c.maybeFinalizeOrderLocked()
}

func (c *bleChannel) maybeFinalizeOrderLocked() {
	if c.orderWriteSeen && c.orderSubscribeSeen {
		c.orderDeterminedOnce.Do(func() { close(c.orderDetermined) })
	}
}

// ---- Peripheral side: matter/io.Transport, backed by a simulated BTP link ----

// blePeripheralTransport is the peripheral-role counterpart to
// matter/ble/transport.go's Handshake and matter/ble/btp.Segmenter, both of
// which only implement the central role (go-matter is exclusively a
// commissioner). Reimplemented independently here rather than exporting a
// peripheral mode from production code that no real caller needs, matching
// this package's existing precedent of standalone protocol reimplementations
// (e.g. case_message.go) for the responder side of things go-matter only
// ever initiates.
type blePeripheralTransport struct {
	ch           *bleChannel
	fragmentSize int

	// Peripheral-role BTP sequence numbers (4.19.4.5): this side's own tx
	// starts at 1, and the central's tx (this side's rx) is expected to
	// start at 0 — the reverse of matter/ble/btp.Segmenter, which
	// implements the central role.
	txNextSeq     uint8
	rxNextSeq     uint8
	pendingAckSeq uint8
	hasPendingAck bool
	rxBuf         []byte
	rxMsgLen      int

	handshakeOnce sync.Once
	handshakeErr  error
}

func newBLEPeripheralTransport(ch *bleChannel) *blePeripheralTransport {
	return &blePeripheralTransport{
		ch:           ch,
		fragmentSize: blePeripheralFragmentSize,
		txNextSeq:    1,
		rxNextSeq:    0,
	}
}

// HandshakeOrderOK reports whether the central's first C1 write was called
// before its first Subscribe call — the order a real device this was
// debugged against required to ever respond at all (see
// matter/ble/transport.go's Handshake doc comment). The order is recorded by
// bleChannel synchronously with those central-side calls themselves (see its
// doc comment for why it can't be inferred from the peripheral side's own
// observation of them); this just blocks until both have happened at least
// once.
func (t *blePeripheralTransport) HandshakeOrderOK(ctx context.Context) (bool, error) {
	select {
	case <-t.ch.orderDetermined:
		t.ch.orderMu.Lock()
		defer t.ch.orderMu.Unlock()
		return t.ch.orderWriteFirst, nil
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

func (t *blePeripheralTransport) Close() error {
	t.ch.close()
	return nil
}

// runHandshake performs the BTP handshake from the peripheral's side:
// receive the (fixed-format, not BTP-segment-framed) handshake request on
// C1, then send the handshake response on C2 once notifications have been
// enabled — whether that happens before or after the request arrives.
// Always eventually responds regardless of that order (unlike the real
// device this was debugged against, which never responds at all if
// Subscribe precedes the write) — HandshakeOrderOK reports the order that
// was actually observed, so a test can assert on it directly instead of
// relying on matter.DefaultCommissioningTimeout (120s) to fail slow if
// matter/ble/transport.go's Handshake regresses to the wrong one.
func (t *blePeripheralTransport) runHandshake() {
	t.handshakeOnce.Do(func() {
		select {
		case <-t.ch.toPeripheral:
		case <-t.ch.closed:
			t.handshakeErr = fmt.Errorf("mockdevice: ble: closed before handshake request arrived")
			return
		}
		select {
		case <-t.ch.subscribed:
		case <-t.ch.closed:
			t.handshakeErr = fmt.Errorf("mockdevice: ble: closed before Subscribe was called")
			return
		}
		resp := []byte{
			0x65,                 // control flags: handshake + management
			0x6C,                 // management opcode: BLE transport handshake
			0x04,                 // selected BTP version
			byte(t.fragmentSize), // fragment size, low byte
			byte(t.fragmentSize >> 8),
			5, // window size
		}
		select {
		case t.ch.toCentral <- resp:
		case <-t.ch.closed:
			t.handshakeErr = fmt.Errorf("mockdevice: ble: closed before handshake response could be sent")
		}
	})
}

// Transmit BTP-segments b (peripheral tx role) and writes each segment to
// the simulated C2 indication channel.
func (t *blePeripheralTransport) Transmit(ctx context.Context, b []byte) error {
	t.runHandshake()
	if t.handshakeErr != nil {
		return t.handshakeErr
	}

	for _, seg := range t.encodeMessage(b) {
		select {
		case t.ch.toCentral <- seg:
		case <-ctx.Done():
			return ctx.Err()
		case <-t.ch.closed:
			return fmt.Errorf("mockdevice: ble: peripheral transport closed")
		}
	}
	return nil
}

// Receive reads simulated C1 write segments until a full message
// reassembles (peripheral rx role, expecting the central's tx to start at
// sequence 0).
func (t *blePeripheralTransport) Receive(ctx context.Context) ([]byte, error) {
	t.runHandshake()
	if t.handshakeErr != nil {
		return nil, t.handshakeErr
	}

	for {
		var seg []byte
		select {
		case seg = <-t.ch.toPeripheral:
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-t.ch.closed:
			return nil, fmt.Errorf("mockdevice: ble: peripheral transport closed")
		}
		msg, ok, err := t.feedSegment(seg)
		if err != nil {
			return nil, err
		}
		if ok {
			return msg, nil
		}
	}
}

// encodeMessage/feedSegment mirror matter/ble/btp.Segmenter's algorithm
// exactly (4.19.4.4), with this type's peripheral-role sequence numbers.
func (t *blePeripheralTransport) encodeMessage(payload []byte) [][]byte {
	const (
		flagStart    = 0x01
		flagContinue = 0x02
		flagEnd      = 0x04
		flagAck      = 0x08
	)
	var segments [][]byte
	remaining := payload
	first := true
	for {
		headerSize := 2
		if first {
			headerSize += 2
		}
		if t.hasPendingAck {
			headerSize++
		}
		capacity := t.fragmentSize - headerSize
		n := len(remaining)
		last := n <= capacity
		if !last {
			n = capacity
		}
		chunk := remaining[:n]
		remaining = remaining[n:]

		var flags byte
		if first {
			flags |= flagStart
		} else {
			flags |= flagContinue
		}
		if last {
			flags |= flagEnd
		}

		seg := make([]byte, 0, headerSize+len(chunk))
		if t.hasPendingAck {
			flags |= flagAck
			seg = append(seg, flags, t.pendingAckSeq)
			t.hasPendingAck = false
		} else {
			seg = append(seg, flags)
		}
		seg = append(seg, t.txNextSeq)
		t.txNextSeq++
		if first {
			seg = append(seg, byte(len(payload)), byte(len(payload)>>8))
		}
		seg = append(seg, chunk...)
		segments = append(segments, seg)

		first = false
		if last {
			break
		}
	}
	return segments
}

func (t *blePeripheralTransport) feedSegment(seg []byte) ([]byte, bool, error) {
	const (
		flagStart    = 0x01
		flagContinue = 0x02
		flagEnd      = 0x04
		flagAck      = 0x08
	)
	if len(seg) < 2 {
		return nil, false, fmt.Errorf("mockdevice: ble: segment too short: %d bytes", len(seg))
	}
	flags := seg[0]
	i := 1
	if flags&flagAck != 0 {
		i++
	}
	if i >= len(seg) {
		return nil, false, fmt.Errorf("mockdevice: ble: segment missing sequence number")
	}
	seqNum := seg[i]
	i++
	if seqNum != t.rxNextSeq {
		return nil, false, fmt.Errorf("mockdevice: ble: unexpected sequence number %d, want %d", seqNum, t.rxNextSeq)
	}
	t.rxNextSeq++
	t.pendingAckSeq = seqNum
	t.hasPendingAck = true

	isStart := flags&flagStart != 0
	isContinue := flags&flagContinue != 0
	isEnd := flags&flagEnd != 0
	if !isStart && !isContinue && !isEnd {
		return nil, false, nil
	}

	if isStart {
		if i+2 > len(seg) {
			return nil, false, fmt.Errorf("mockdevice: ble: segment missing message length")
		}
		t.rxMsgLen = int(seg[i]) | int(seg[i+1])<<8
		i += 2
		t.rxBuf = make([]byte, 0, t.rxMsgLen)
	}
	t.rxBuf = append(t.rxBuf, seg[i:]...)

	if !isEnd {
		return nil, false, nil
	}
	msg := t.rxBuf
	t.rxBuf = nil
	if len(msg) != t.rxMsgLen {
		return nil, false, fmt.Errorf("mockdevice: ble: reassembled message length %d, want %d", len(msg), t.rxMsgLen)
	}
	return msg, true, nil
}

// ---- Central side: go-ble's raw interfaces, as a real ble.Scanner would return ----

// matterServiceAdvertisementData encodes the 8-byte Matter BLE service data
// payload matter/ble/service.go's newAdvertisingDataFromBytes decodes:
// opcode (commissionable), version+discriminator, vendor ID, product ID,
// flags (4.19.4.5.6).
func matterServiceAdvertisementData(discriminator, vendorID, productID uint16) []byte {
	b := make([]byte, 8)
	b[0] = 0x00 // OpCodeCommissionable
	binary.LittleEndian.PutUint16(b[1:3], discriminator&0x0FFF)
	binary.LittleEndian.PutUint16(b[3:5], vendorID)
	binary.LittleEndian.PutUint16(b[5:7], productID)
	b[7] = 0x00
	return b
}

type fakeManufacturer struct{}

func (fakeManufacturer) ID() int            { return -1 }
func (fakeManufacturer) Name() string       { return "" }
func (fakeManufacturer) Data() []byte       { return nil }
func (fakeManufacturer) MarshalObject() any { return map[string]any{} }
func (fakeManufacturer) String() string     { return "{}" }

var errFakeCharacteristicUnused = errors.New("mockdevice: ble: characteristic stub is not backed by a real transport")

// fakeBLECharacteristic is a display-only stand-in for C1/C2/C3: the actual
// read/write/notify traffic goes through fakeBLETransport instead (this
// mock's Service.Open builds one directly, bypassing the real
// LookupCharacteristic-driven wiring go-ble's own service.Open does, since
// this fake implements ble.Service.Open itself rather than reusing that
// concrete type), so these methods are never called by matter/ble in
// practice — only exist to satisfy ble.Characteristic for
// Characteristics()/LookupCharacteristic(), which matter/ble.service uses
// only for logging/display.
type fakeBLECharacteristic struct {
	uuid ble.UUID
	name string
}

func (c *fakeBLECharacteristic) Service() ble.Service      { return nil }
func (c *fakeBLECharacteristic) UUID() ble.UUID            { return c.uuid }
func (c *fakeBLECharacteristic) Name() string              { return c.name }
func (c *fakeBLECharacteristic) ID() string                { return "" }
func (c *fakeBLECharacteristic) Read() ([]byte, error)     { return nil, errFakeCharacteristicUnused }
func (c *fakeBLECharacteristic) Write([]byte) (int, error) { return 0, errFakeCharacteristicUnused }
func (c *fakeBLECharacteristic) WriteWithoutResponse([]byte) (int, error) {
	return 0, errFakeCharacteristicUnused
}
func (c *fakeBLECharacteristic) Notify(ble.OnCharacteristicNotification) error {
	return errFakeCharacteristicUnused
}
func (c *fakeBLECharacteristic) MarshalObject() any { return c.uuid.String() }
func (c *fakeBLECharacteristic) String() string     { return c.uuid.String() }

// fakeBLETransport implements ble.Transport (the interface matter/ble.newTransport
// wraps with Handshake) directly over a bleChannel, instead of a real GATT
// connection.
type fakeBLETransport struct {
	ch *bleChannel
}

func (t *fakeBLETransport) Open() error  { return nil }
func (t *fakeBLETransport) Close() error { return nil }

func (t *fakeBLETransport) Subscribe() error {
	t.ch.recordFirstSubscribe()
	t.ch.subscribe()
	return nil
}

func (t *fakeBLETransport) WriteCharacteristic() (ble.Characteristic, error) {
	return &fakeBLECharacteristic{uuid: matterble.C1UUID, name: "C1 (Client TX Buffer)"}, nil
}

func (t *fakeBLETransport) ReadCharacteristic() (ble.Characteristic, error) {
	return nil, errFakeCharacteristicUnused
}

func (t *fakeBLETransport) NotifyCharacteristic() (ble.Characteristic, error) {
	return &fakeBLECharacteristic{uuid: matterble.C2UUID, name: "C2 (Client RX Buffer)"}, nil
}

func (t *fakeBLETransport) Read(ctx context.Context) ([]byte, error) {
	select {
	case b := <-t.ch.toCentral:
		return b, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-t.ch.closed:
		return nil, fmt.Errorf("mockdevice: ble: central transport closed")
	}
}

func (t *fakeBLETransport) Write(ctx context.Context, data []byte) (int, error) {
	return t.WriteWithoutResponse(ctx, data)
}

func (t *fakeBLETransport) WriteWithoutResponse(ctx context.Context, data []byte) (int, error) {
	t.ch.recordFirstWrite()
	select {
	case t.ch.toPeripheral <- data:
		return len(data), nil
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-t.ch.closed:
		return 0, fmt.Errorf("mockdevice: ble: central transport closed")
	}
}

// fakeBLEService implements ble.Service directly (rather than reusing
// go-ble's own concrete service type, which is built around a real
// characteristic table matter/ble's package-private device/service types
// wire up from a real scan). Its Open ignores the
// ble.ServiceTransportOption values matter/ble/service.go's Open always
// passes (WithTransportWriteUUID(C1UUID), WithTransportNotifyUUID(C2UUID)):
// those close over an unexported options type this package has no access
// to construct or inspect, but since the caller is always go-matter's own
// fixed C1/C2 wiring, there's nothing to actually branch on.
type fakeBLEService struct {
	ch            *bleChannel
	discriminator uint16
	vendorID      uint16
	productID     uint16
}

func (s *fakeBLEService) Device() ble.Device { return nil }
func (s *fakeBLEService) UUID() ble.UUID     { return ble.NewUUIDFromUUID16(matterble.MatterServiceID) }
func (s *fakeBLEService) Name() string       { return "Matter Profile ID" }
func (s *fakeBLEService) Data() []byte {
	return matterServiceAdvertisementData(s.discriminator, s.vendorID, s.productID)
}

func (s *fakeBLEService) Characteristics() []ble.Characteristic {
	return []ble.Characteristic{
		&fakeBLECharacteristic{uuid: matterble.C1UUID, name: "C1 (Client TX Buffer)"},
		&fakeBLECharacteristic{uuid: matterble.C2UUID, name: "C2 (Client RX Buffer)"},
		&fakeBLECharacteristic{uuid: matterble.C3UUID, name: "C3 (Additional Commissioning Data)"},
	}
}

func (s *fakeBLEService) LookupCharacteristic(uuid any) (ble.Characteristic, bool) {
	for _, c := range s.Characteristics() {
		if lookup, err := ble.NewUUIDFrom(uuid); err == nil && lookup.Equal(c.UUID()) {
			return c, true
		}
	}
	return nil, false
}

func (s *fakeBLEService) Open(_ ...ble.ServiceTransportOption) (ble.Transport, error) {
	return &fakeBLETransport{ch: s.ch}, nil
}

func (s *fakeBLEService) MarshalObject() any { return s.UUID().String() }
func (s *fakeBLEService) String() string     { return s.UUID().String() }

// fakeBLEDevice implements ble.Device over a single fakeBLEService.
type fakeBLEDevice struct {
	addr    ble.Address
	service *fakeBLEService

	mu        sync.Mutex
	connected bool
}

func (d *fakeBLEDevice) Manufacturer() ble.Manufacturer { return fakeManufacturer{} }
func (d *fakeBLEDevice) LocalName() string              { return "MOCK_" + d.addr.String() }
func (d *fakeBLEDevice) Address() ble.Address           { return d.addr }
func (d *fakeBLEDevice) Services() []ble.Service        { return []ble.Service{d.service} }
func (d *fakeBLEDevice) RSSI() int                      { return -40 }
func (d *fakeBLEDevice) DiscoveredAt() time.Time        { return time.Time{} }
func (d *fakeBLEDevice) ModifiedAt() time.Time          { return time.Time{} }
func (d *fakeBLEDevice) LastSeenAt() time.Time          { return time.Time{} }

func (d *fakeBLEDevice) Connect(context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.connected = true
	return nil
}

func (d *fakeBLEDevice) Disconnect() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.connected = false
	return nil
}

func (d *fakeBLEDevice) IsConnected() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.connected
}

func (d *fakeBLEDevice) LookupService(uuid any) (ble.Service, bool) {
	lookup, err := ble.NewUUIDFrom(uuid)
	if err != nil || !lookup.Equal(d.service.UUID()) {
		return nil, false
	}
	return d.service, true
}

func (d *fakeBLEDevice) String() string { return d.LocalName() }

// fakeBLECentral implements matter/ble.Central over a single simulated
// peripheral, for injection via matter.WithCommissionerCentral.
type fakeBLECentral struct {
	rawDev ble.Device       // fed to a ble.ScanHandler by Scan, matching a real scanner
	dev    matterble.Device // the same device, wrapped as DiscoveredDevices returns it
}

func newFakeBLECentral(ch *bleChannel, discriminator, vendorID, productID uint16) matterble.Central {
	bleDev := &fakeBLEDevice{
		addr: ble.Address("mockdevice-ble"),
		service: &fakeBLEService{
			ch:            ch,
			discriminator: discriminator,
			vendorID:      vendorID,
			productID:     productID,
		},
	}
	matterDev, err := matterble.NewDeviceWith(bleDev, bleDev.service)
	if err != nil {
		// bleDev.service.Data() is always the well-formed 8-byte blob this
		// same file constructs above, so NewDeviceWith's advertisement-data
		// parsing can't fail.
		panic(fmt.Sprintf("mockdevice: ble: NewDeviceWith: %v", err))
	}
	return &fakeBLECentral{rawDev: bleDev, dev: matterDev}
}

func (c *fakeBLECentral) DiscoveredDevices() []matterble.Device {
	return []matterble.Device{c.dev}
}

// LookupDeviceByDiscriminator is unused by matter/commissioner_impl.go's
// Discover/commissionMatchingDevice (both go through DiscoveredDevices
// instead), but implemented for interface completeness and any future
// caller: this mock only ever has the one device, so it's returned
// unconditionally rather than actually comparing v against its
// discriminator.
func (c *fakeBLECentral) LookupDeviceByDiscriminator(any) (matterble.Device, error) {
	return c.dev, nil
}

func (c *fakeBLECentral) Scan(_ context.Context, opts ...ble.ScannerOption) error {
	for _, opt := range opts {
		if h, ok := opt.(ble.ScanHandler); ok {
			h(c.rawDev)
		}
	}
	return nil
}
