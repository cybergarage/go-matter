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

package mockdevice

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter/encoding/message"
	"github.com/cybergarage/go-matter/matter/io"
	"github.com/cybergarage/go-matter/matter/types"
)

// defaultDiscriminator/defaultPasscode/defaultVendorID/defaultProductID are
// the fallback values for Device, distinct from any real device's actual
// values — this mock is only ever addressed via a synthetic Manual Pairing
// Code a test constructs itself, matching the same discriminator/passcode.
const (
	defaultDiscriminator uint16 = 0x0F00
	defaultPasscode      uint32 = 20202021
	defaultVendorID      uint16 = 0xFFF1
	defaultProductID     uint16 = 0x8000
)

// Device is an in-process, loopback-UDP fake Matter device: the responder
// side of PASE and CASE, plus a minimal Interaction Model server, handling
// exactly the commissioning sequence a commissioner with an already-
// network-connected target performs (no Network Commissioning cluster
// traffic — see registerGeneralCommissioningHandlers'/commissionNetwork's
// requireNetwork=false skip path in matter/commissioning_impl.go).
type Device struct {
	discriminator uint16
	passcode      types.Passcode
	vendorID      uint16
	productID     uint16

	fs *fabricState

	conn          *net.UDPConn
	paseTransport io.Transport
	caseTransport io.Transport
	closer        func() error
	// expectNetworkCommissioning is true for a BLE-simulated Device
	// (StartBLE): commissionWithSession's requireNetwork=true for the BLE
	// transport (matter/device_ble.go) means the commissioner sends
	// AddOrUpdateWiFiNetwork/ConnectNetwork over the PASE session, after
	// AddNOC but before moving on to CASE — serve must keep its PASE
	// Interaction Model loop running for that, not stop as soon as AddNOC
	// finishes the way Start's UDP mode (requireNetwork=false, no Network
	// Commissioning traffic at all) correctly does.
	expectNetworkCommissioning bool

	commissioningComplete chan struct{}
	completeOnce          sync.Once

	wg sync.WaitGroup
}

// Option configures a Device.
type Option func(*Device)

// WithDiscriminator sets the 12-bit discriminator this device advertises.
func WithDiscriminator(d uint16) Option {
	return func(dev *Device) { dev.discriminator = d }
}

// WithPasscode sets the PASE passcode this device expects.
func WithPasscode(p uint32) Option {
	return func(dev *Device) { dev.passcode = types.NewPasscode(p) }
}

// WithVendorID sets the vendor ID this device advertises.
func WithVendorID(v uint16) Option {
	return func(dev *Device) { dev.vendorID = v }
}

// WithProductID sets the product ID this device advertises.
func WithProductID(p uint16) Option {
	return func(dev *Device) { dev.productID = p }
}

// New creates a Device with the given options applied over synthetic
// defaults, and a freshly generated attestation identity.
func New(opts ...Option) (*Device, error) {
	attestation, err := generateAttestationIdentity()
	if err != nil {
		return nil, fmt.Errorf("mockdevice: %w", err)
	}
	dev := &Device{
		discriminator:         defaultDiscriminator,
		passcode:              types.NewPasscode(defaultPasscode),
		vendorID:              defaultVendorID,
		productID:             defaultProductID,
		fs:                    newFabricState(attestation),
		commissioningComplete: make(chan struct{}),
	}
	for _, opt := range opts {
		opt(dev)
	}
	return dev, nil
}

// Discriminator returns this device's advertised discriminator.
func (d *Device) Discriminator() uint16 { return d.discriminator }

// Passcode returns this device's PASE passcode.
func (d *Device) Passcode() types.Passcode { return d.passcode }

// VendorID returns this device's advertised vendor ID.
func (d *Device) VendorID() uint16 { return d.vendorID }

// ProductID returns this device's advertised product ID.
func (d *Device) ProductID() uint16 { return d.productID }

// Start binds a loopback UDP socket and begins serving commissioning
// traffic on a background goroutine.
func (d *Device) Start() error {
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("mockdevice: resolve loopback address: %w", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("mockdevice: listen: %w", err)
	}
	d.conn = conn
	udp := &udpDeviceTransport{conn: conn}
	d.paseTransport = udp
	d.caseTransport = udp
	d.closer = conn.Close
	d.wg.Add(1)
	go d.serve()
	return nil
}

// StartBLE begins serving PASE (and, over it, Network Commissioning/AddNOC)
// over paseTransport instead of a loopback UDP socket, simulating a BLE
// peripheral for tests exercising matter.WithCommissionerCentral instead of
// a real Bluetooth adapter. CASE, which a real commissioner establishes
// separately over the operational network after Wi-Fi provisioning (see
// matter/operational_transport.go), still runs over a loopback UDP socket
// exactly like Start's — this method opens one and pairs it with
// NewFakeOperationalDiscoverer for that purpose. closer is called by Stop to
// unblock paseTransport's Receive and let serve's goroutine exit; the UDP
// socket opened here is closed alongside it automatically.
func (d *Device) StartBLE(paseTransport io.Transport, closer func() error) error {
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("mockdevice: resolve loopback address: %w", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("mockdevice: listen: %w", err)
	}
	d.conn = conn
	d.paseTransport = paseTransport
	d.caseTransport = &udpDeviceTransport{conn: conn}
	d.expectNetworkCommissioning = true
	d.closer = func() error {
		udpErr := conn.Close()
		if err := closer(); err != nil {
			return err
		}
		return udpErr
	}
	d.wg.Add(1)
	go d.serve()
	return nil
}

// Stop shuts down the device's transport and waits for its serve goroutine
// (and everything it spawned) to exit.
func (d *Device) Stop() error {
	if d.closer == nil {
		return nil
	}
	err := d.closer()
	d.wg.Wait()
	return err
}

// Addr returns the loopback address/port this device is listening on. Only
// valid after Start.
func (d *Device) Addr() *net.UDPAddr {
	addr, ok := d.conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		// d.conn is always created by net.ListenUDP in Start, which always
		// returns a *net.UDPConn whose LocalAddr is always a *net.UDPAddr.
		panic("mockdevice: UDP connection's LocalAddr is not a *net.UDPAddr")
	}
	return addr
}

// CommissioningCompleted returns a channel that is closed once this device
// has handled a CommissioningComplete command — the strong end-to-end
// assertion hook for a full commissioning test.
func (d *Device) CommissioningCompleted() <-chan struct{} {
	return d.commissioningComplete
}

// FabricID returns the fabric ID this device joined, valid only after
// AddNOC has been handled (i.e. after CommissioningCompleted would fire).
func (d *Device) FabricID() uint64 { return d.fs.fabricID }

// NodeID returns the operational node ID this device was assigned, valid
// only after AddNOC has been handled.
func (d *Device) NodeID() uint64 { return d.fs.nodeID }

func (d *Device) signalCommissioningComplete() {
	d.completeOnce.Do(func() { close(d.commissioningComplete) })
}

// serve runs PASE to completion, then serves Interaction Model requests
// over the resulting secure session until AddNOC succeeds (the last
// PASE-phase step before a commissioner moves on to Network Commissioning —
// skipped here, see the Device doc comment — and then CASE), then accepts
// and serves any number of CASE sessions in turn (the commissioning-time
// one, and any later Commissioner.Connect reconnection) for as long as this
// Device runs — see the CASE dispatch loop below for why a single
// handleCASE-then-serve-forever pass isn't enough.
func (d *Device) serve() {
	defer d.wg.Done()
	ctx := context.Background()

	paseSess, err := handlePASE(ctx, d.paseTransport, d.passcode)
	if err != nil {
		log.Debugf("mockdevice: PASE ended: %v", err)
		return
	}

	paseIM := newIMServer(paseSess)
	addNOCDone := make(chan struct{})
	networkCommissioningDone := make(chan struct{})
	registerGeneralCommissioningHandlers(paseIM, d.signalCommissioningComplete)
	registerOperationalCredentialsHandlers(paseIM, d.fs, paseSess.SessionKeys().AttestationChallenge, func() {
		close(addNOCDone)
	})
	// Only exercised by a BLE-simulated Device (commissionNetwork requires
	// it — see commissionWithSession's requireNetwork=true for the BLE
	// transport in matter/device_ble.go); UDP-mode commissioning never
	// invokes it, since requireNetwork=false there skips Network
	// Commissioning entirely when no Wi-Fi config is supplied.
	registerNetworkCommissioningHandlers(paseIM, func() {
		close(networkCommissioningDone)
	})

	for {
		if err := paseIM.serveOne(); err != nil {
			log.Debugf("mockdevice: IM (PASE) ended: %v", err)
			return
		}
		select {
		case <-addNOCDone:
		default:
			continue
		}
		if d.expectNetworkCommissioning {
			select {
			case <-networkCommissioningDone:
			default:
				continue
			}
		}
		break
	}

	// This goroutine becomes the CASE dispatch pump: the sole reader of
	// d.caseTransport's physical socket for the rest of this Device's
	// life, demultiplexing every datagram it reads — the commissioning-
	// time handshake, and any number of later Commissioner.Connect
	// reconnections, all arriving on this same shared socket (mockdevice's
	// fake discoverers always report this Device's one listening port for
	// both commissionable- and operational-node lookups; see
	// fakenode.go's Search) — by peeking each raw datagram's cleartext
	// SessionID and handing it to either the currently active CASE
	// session's channelTransport, or a freshly spawned handshake attempt's
	// own channelTransport.
	//
	// A per-session/per-attempt channelTransport (rather than a single
	// shared transport with a one-packet pushback buffer) is required
	// because session.SecureSession.Receive
	// (matter/protocol/session/session_impl.go) transparently loops past
	// standalone MRP acks and foreign-session packets, re-reading its
	// transport internally without ever returning control to its caller.
	// A single imServer.serveOne call can therefore silently pull an
	// unbounded number of physical packets, not just the one routed to
	// it — so if every session read the same shared transport directly, an
	// old session still blocked past a trailing ack could silently steal
	// and discard a brand new handshake's Sigma1 before this dispatch loop
	// ever saw it, and Connect would simply time out. Each session (and
	// handshake attempt) instead runs on its own goroutine, reading only
	// its own channel — its internal retry loop can never observe a packet
	// this pump decided belongs to someone else.
	var sessionsWG sync.WaitGroup
	defer sessionsWG.Wait()

	var mu sync.Mutex
	// pendingCh is the channel of a CASE handshake currently in progress
	// (Sigma1..SigmaFinished), if any: every message of that exchange
	// travels over the unsecured session (header SessionID 0, spec
	// 4.14.1.1), the same as Sigma1 itself, so this — not the header's
	// SessionID, which can't tell two different unsecured exchanges apart
	// — is what lets a multi-packet handshake's later messages (e.g.
	// Sigma3) reach the same goroutine/channel Sigma1 started, instead of
	// each spawning a new handshake attempt of its own.
	var pendingCh *channelTransport
	var activeSessionID message.SessionID
	var activeCh *channelTransport
	var haveActiveSession bool
	// allCh tracks every channelTransport ever created, so that once this
	// pump's own physical Receive errors (Device.Stop closed the socket),
	// every session/handshake goroutine still blocked on one — including
	// stale ones no longer pendingCh/activeCh — gets unblocked too. See
	// channelTransport's doc comment for why closing, not context
	// cancellation, is what does this.
	var allCh []*channelTransport

	for {
		raw, err := d.caseTransport.Receive(ctx)
		if err != nil {
			log.Debugf("mockdevice: CASE dispatch: transport ended: %v", err)
			mu.Lock()
			for _, c := range allCh {
				c.close()
			}
			mu.Unlock()
			return
		}
		hdr, err := message.NewHeaderFromBytes(raw)
		if err != nil {
			log.Debugf("mockdevice: CASE dispatch: malformed frame header: %v", err)
			continue
		}

		mu.Lock()
		switch {
		case haveActiveSession && hdr.SessionID() == activeSessionID:
			ch := activeCh
			mu.Unlock()
			ch.feed(raw)
			continue
		case pendingCh != nil && hdr.SessionID() == 0:
			ch := pendingCh
			mu.Unlock()
			ch.feed(raw)
			continue
		}
		// Neither the active session nor an in-progress handshake: start a
		// fresh CASE handshake attempt on its own goroutine, so this pump
		// keeps reading regardless of how long it takes. handleCASE's own
		// receiveNonAckMessage discards raw harmlessly if it turns out not
		// to actually be a Sigma1 (e.g. a stray unsecured MRP ack, or a
		// stray encrypted packet left over from a session that just
		// ended).
		attemptCh := newChannelTransport(d.caseTransport)
		pendingCh = attemptCh
		allCh = append(allCh, attemptCh)
		mu.Unlock()
		attemptCh.feed(raw)
		sessionsWG.Go(func() {
			d.serveCASESession(ctx, attemptCh, &mu, &pendingCh, &activeSessionID, &activeCh, &haveActiveSession)
		})
	}
}

// serveCASESession runs one CASE handshake attempt over ch to completion
// and, if it succeeds, serves Interaction Model requests over the
// resulting session until it ends — recording itself as the dispatch
// pump's active session for as long as it's the most recently established
// one. mu guards pendingCh/activeSessionID/activeCh/haveActiveSession,
// shared with serve's dispatch loop.
func (d *Device) serveCASESession(ctx context.Context, ch *channelTransport, mu *sync.Mutex, pendingCh **channelTransport, activeSessionID *message.SessionID, activeCh **channelTransport, haveActiveSession *bool) {
	caseSess, err := handleCASE(ctx, ch, d.fs)

	mu.Lock()
	if *pendingCh == ch {
		*pendingCh = nil
	}
	if err == nil {
		*activeSessionID = caseSess.SessionKeys().InitiatorSessionID()
		*activeCh = ch
		*haveActiveSession = true
	}
	mu.Unlock()

	if err != nil {
		log.Debugf("mockdevice: CASE handshake attempt failed: %v", err)
		return
	}

	caseIM := newIMServer(caseSess)
	registerCASEHandlers(d, caseIM)

	for {
		if err := caseIM.serveOne(); err != nil {
			log.Debugf("mockdevice: IM (CASE) ended: %v", err)
			mu.Lock()
			if *activeCh == ch {
				*haveActiveSession = false
				*activeCh = nil
			}
			mu.Unlock()
			return
		}
	}
}

// registerCASEHandlers wires every operational-phase (CASE) cluster handler
// onto a freshly created caseIM. Called once per CASE session — including
// every later Commissioner.Connect reconnection — since imServer's handler
// map is per-instance, not shared across sessions.
func registerCASEHandlers(d *Device, caseIM *imServer) {
	registerGeneralCommissioningHandlers(caseIM, d.signalCommissioningComplete)
	registerDescriptorHandlers(caseIM, d)
	registerBasicInformationHandlers(caseIM, d)
	registerAccessControlHandlers(caseIM, d)
	registerGeneralDiagnosticsHandlers(caseIM, d)
}

// udpDeviceTransport adapts a bound *net.UDPConn to io.Transport for a
// single peer: it learns that peer's address from the first packet it
// receives (mirroring how a real device's socket only ever hears from the
// one commissioner currently pairing with it) and sends every subsequent
// Transmit to that same address. This is also what lets
// resolveOperationalTransport (matter/operational_transport.go) on the
// commissioner side reuse its PASE connection for CASE: both phases talk to
// the exact same address:port pair.
type udpDeviceTransport struct {
	conn *net.UDPConn

	mu       sync.Mutex
	peerAddr *net.UDPAddr
}

func (t *udpDeviceTransport) Transmit(ctx context.Context, b []byte) error {
	t.mu.Lock()
	peer := t.peerAddr
	t.mu.Unlock()
	if peer == nil {
		return fmt.Errorf("mockdevice: transmit before any peer has been heard from")
	}
	if err := t.setWriteDeadline(ctx); err != nil {
		return err
	}
	_, err := t.conn.WriteToUDP(b, peer)
	return err
}

func (t *udpDeviceTransport) Receive(ctx context.Context) ([]byte, error) {
	if err := t.setReadDeadline(ctx); err != nil {
		return nil, err
	}
	buf := make([]byte, 16*1024)
	n, addr, err := t.conn.ReadFromUDP(buf)
	if err != nil {
		return nil, err
	}
	t.mu.Lock()
	t.peerAddr = addr
	t.mu.Unlock()
	return buf[:n], nil
}

func (t *udpDeviceTransport) setReadDeadline(ctx context.Context) error {
	if deadline, ok := ctx.Deadline(); ok {
		return t.conn.SetReadDeadline(deadline)
	}
	return t.conn.SetReadDeadline(time.Time{})
}

func (t *udpDeviceTransport) setWriteDeadline(ctx context.Context) error {
	if deadline, ok := ctx.Deadline(); ok {
		return t.conn.SetWriteDeadline(deadline)
	}
	return t.conn.SetWriteDeadline(time.Time{})
}
