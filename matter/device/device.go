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

package device

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter/credentials"
	"github.com/cybergarage/go-matter/matter/crypto"
	"github.com/cybergarage/go-matter/matter/encoding/message"
	"github.com/cybergarage/go-matter/matter/mdns"
	"github.com/cybergarage/go-matter/matter/protocol/im"
	"github.com/cybergarage/go-matter/matter/protocol/pase"
	"github.com/cybergarage/go-matter/matter/protocol/session"
	"github.com/cybergarage/go-matter/matter/store"
	"github.com/cybergarage/go-matter/matter/types"
)

// DefaultAddress is where a Device listens unless WithAddress says
// otherwise: every interface, on the Matter port.
var DefaultAddress = fmt.Sprintf(":%d", mdns.Port)

// DefaultPBKDFIterations is the iteration count WithPasscode derives a
// verifier with.
const DefaultPBKDFIterations = crypto.PBKDBFIterationsMin

// maxMessageSize is the largest Matter message over UDP (Matter Core 4.4.4,
// the IPv6 minimum MTU).
const maxMessageSize = 1280

// peerQueueLength bounds the messages queued for one exchange or session;
// more are dropped, as a congested UDP socket would.
const peerQueueLength = 16

// ErrNoVerifier is returned by New when neither WithVerifier nor
// WithPasscode was given.
var ErrNoVerifier = errors.New("device: a PASE verifier or passcode is required")

// Session is a secure session a Device has established with a peer. The
// device serves the Interaction Model on it.
type Session struct {
	keys      pase.SessionKeys
	peer      *net.UDPAddr
	transport *peerTransport
	secure    session.SecureSession
}

// Keys returns the session's keys, as the PASE responder derived them.
func (s *Session) Keys() pase.SessionKeys {
	return s.keys
}

// Peer returns the address the session was established from.
func (s *Session) Peer() net.Addr {
	return s.peer
}

// Option configures a Device.
type Option func(*Device) error

// WithVerifier sets the PASE verifier the device authenticates
// commissioners with.
func WithVerifier(v pase.Verifier) Option {
	return func(d *Device) error {
		if err := v.Validate(); err != nil {
			return err
		}
		d.verifier = v
		d.hasVerifier = true
		return nil
	}
}

// WithPasscode derives a PASE verifier from passcode with a random salt and
// DefaultPBKDFIterations. A product should be provisioned with a verifier
// instead, so the passcode is not kept on the device.
func WithPasscode(passcode types.Passcode) Option {
	return func(d *Device) error {
		v, err := pase.NewRandomSaltVerifier(passcode, DefaultPBKDFIterations)
		if err != nil {
			return err
		}
		d.verifier = v
		d.hasVerifier = true
		return nil
	}
}

// WithAddress sets the UDP address to listen on, such as ":5540" or
// "127.0.0.1:0".
func WithAddress(addr string) Option {
	return func(d *Device) error {
		d.address = addr
		return nil
	}
}

// WithDiscriminator sets the 12-bit discriminator.
func WithDiscriminator(discriminator uint16) Option {
	return func(d *Device) error {
		d.service.Discriminator = discriminator
		return nil
	}
}

// WithVendorID sets the vendor ID.
func WithVendorID(vid uint16) Option {
	return func(d *Device) error {
		d.service.VendorID = vid
		return nil
	}
}

// WithProductID sets the product ID.
func WithProductID(pid uint16) Option {
	return func(d *Device) error {
		d.service.ProductID = pid
		return nil
	}
}

// WithDeviceType sets the primary device type advertised in DT and _T.
func WithDeviceType(deviceType uint32) Option {
	return func(d *Device) error {
		d.service.DeviceType = deviceType
		return nil
	}
}

// WithDeviceName sets the device name advertised in DN.
func WithDeviceName(name string) Option {
	return func(d *Device) error {
		d.service.DeviceName = name
		return nil
	}
}

// WithAdvertiser sets the Advertiser the device publishes its
// commissionable service through, replacing the default MDNSAdvertiser.
// nil advertises nothing, for a device a commissioner reaches by address.
func WithAdvertiser(a Advertiser) Option {
	return func(d *Device) error {
		d.advertiser = a
		return nil
	}
}

// WithDeviceStore sets where the device persists its fabrics, ACLs, group
// keys and counters. The default keeps them in memory, so they do not
// survive the process.
func WithDeviceStore(s store.DeviceStore) Option {
	return func(d *Device) error {
		d.store = s
		return nil
	}
}

// WithAttestationProvider sets the attestation credentials (DAC, PAI and
// Certification Declaration) the device proves it is a certified product
// with. Without one, the device cannot be commissioned: it answers the
// Operational Credentials cluster's attestation and CSR requests with
// Failure. matter/credentials/testcreds provides the Matter SDK's test
// credentials for development.
func WithAttestationProvider(p credentials.AttestationProvider) Option {
	return func(d *Device) error {
		d.attestation = p
		return nil
	}
}

// WithSupportedFabrics sets how many fabrics the device can join, at least
// DefaultSupportedFabrics and at most 254 (Matter Core 11.18.5.3).
func WithSupportedFabrics(n int) Option {
	return func(d *Device) error {
		if n < DefaultSupportedFabrics || int(store.MaxFabricIndex) < n {
			return fmt.Errorf("device: supported fabrics %d is outside %d..%d", n, DefaultSupportedFabrics, store.MaxFabricIndex)
		}
		d.supportedFabrics = uint8(n)
		return nil
	}
}

// WithSessionHandler sets the function called, on its own goroutine, each
// time a commissioner establishes a PASE session.
func WithSessionHandler(h func(*Session)) Option {
	return func(d *Device) error {
		d.onSession = h
		return nil
	}
}

// Device is a Matter device that can be commissioned over IP.
type Device struct {
	mu          sync.Mutex
	address     string
	verifier    pase.Verifier
	hasVerifier bool
	service     CommissionableService
	advertiser  Advertiser
	onSession   func(*Session)
	store       store.DeviceStore
	attestation credentials.AttestationProvider
	imServer    *im.Server
	failSafe    *failSafe

	supportedFabrics uint8

	conn   *net.UDPConn
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	// pase is the unsecured PASE exchange in progress, keyed by the
	// initiator's address; a device runs one at a time.
	pase     *peerTransport
	paseAddr string
	sessions map[types.SessionID]*Session
}

// New returns a Device configured by opts. It does not touch the network
// until Start.
func New(opts ...Option) (*Device, error) {
	d := &Device{
		mu:          sync.Mutex{},
		address:     DefaultAddress,
		verifier:    pase.Verifier{},
		hasVerifier: false,
		service: CommissionableService{
			InstanceName:      NewInstanceName(),
			Hostname:          NewHostname(),
			CommissioningMode: mdns.CommissioningModePasscode,
		},
		advertiser:  NewMDNSAdvertiser(),
		onSession:   nil,
		store:       nil,
		attestation: nil,
		imServer:    im.NewServer(),
		failSafe:    nil,
		sessions:    map[types.SessionID]*Session{},

		supportedFabrics: DefaultSupportedFabrics,
	}
	for _, opt := range opts {
		if err := opt(d); err != nil {
			return nil, err
		}
	}
	if !d.hasVerifier {
		return nil, ErrNoVerifier
	}
	if d.service.Discriminator > MaxDiscriminator {
		return nil, fmt.Errorf("device: discriminator 0x%X exceeds 12 bits", d.service.Discriminator)
	}
	if d.store == nil {
		d.store = store.NewMemDeviceStore()
	}
	d.failSafe = newFailSafe(d.store)
	newGeneralCommissioning(d.failSafe, d.isCASESession).register(d.imServer)
	newOperationalCredentials(d.store, d.failSafe, d.attestation, d.supportedFabrics).register(d.imServer)
	return d, nil
}

// isCASESession reports whether sess was established with CASE. The device
// only establishes PASE sessions so far.
func (d *Device) isCASESession(im.SecureSession) bool {
	return false
}

// Start listens on the configured address and publishes the commissionable
// service, if an Advertiser was given.
func (d *Device) Start() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.conn != nil {
		return fmt.Errorf("device: already started")
	}
	addr, err := net.ResolveUDPAddr("udp", d.address)
	if err != nil {
		return fmt.Errorf("device: resolve %s: %w", d.address, err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("device: listen %s: %w", d.address, err)
	}
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		_ = conn.Close()
		return fmt.Errorf("device: unexpected local address %v", conn.LocalAddr())
	}
	d.service.Port = local.Port
	if err := d.service.Validate(); err != nil {
		_ = conn.Close()
		return err
	}
	if d.advertiser != nil {
		if err := d.advertiser.AdvertiseCommissionable(d.service); err != nil {
			_ = conn.Close()
			return fmt.Errorf("device: advertise: %w", err)
		}
	}
	d.conn = conn
	d.ctx, d.cancel = context.WithCancel(context.Background())
	d.wg.Add(1)
	go d.serve(conn)
	return nil
}

// Stop withdraws the advertisement, closes the socket, and waits for the
// exchanges in progress to end.
func (d *Device) Stop() error {
	d.mu.Lock()
	conn := d.conn
	if conn == nil {
		d.mu.Unlock()
		return nil
	}
	d.conn = nil
	d.cancel()
	for id, sess := range d.sessions {
		sess.transport.close()
		delete(d.sessions, id)
	}
	d.mu.Unlock()
	d.failSafe.close()

	var errs []error
	if d.advertiser != nil {
		if err := d.advertiser.Withdraw(); err != nil {
			errs = append(errs, fmt.Errorf("device: withdraw: %w", err))
		}
	}
	if err := conn.Close(); err != nil {
		errs = append(errs, err)
	}
	d.wg.Wait()
	return errors.Join(errs...)
}

// Addr returns the address the device listens on, or nil before Start.
func (d *Device) Addr() net.Addr {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.conn == nil {
		return nil
	}
	return d.conn.LocalAddr()
}

// CommissionableService returns the service the device advertises. Its
// Port is set once the device has started.
func (d *Device) CommissionableService() CommissionableService {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.service
}

// Verifier returns the PASE verifier the device authenticates with.
func (d *Device) Verifier() pase.Verifier {
	return d.verifier
}

func (d *Device) serve(conn *net.UDPConn) {
	defer d.wg.Done()
	buf := make([]byte, maxMessageSize)
	for {
		n, peer, err := conn.ReadFromUDP(buf)
		if err != nil {
			if d.ctx.Err() == nil {
				log.Errorf("device: read: %v", err)
			}
			return
		}
		d.dispatch(conn, bytes.Clone(buf[:n]), peer)
	}
}

// dispatch routes one datagram: an unsecured message to the PASE exchange
// with its sender, starting one on a PBKDFParamRequest, and a secured
// message to the session its session ID names.
func (d *Device) dispatch(conn *net.UDPConn, b []byte, peer *net.UDPAddr) {
	header, err := message.NewHeaderFromBytes(b)
	if err != nil {
		log.Debugf("device: drop malformed message from %s: %v", peer, err)
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if sid := header.SessionID(); sid != 0 {
		sess, ok := d.sessions[sid]
		if !ok {
			log.Debugf("device: drop message for unknown session %d from %s", sid, peer)
			return
		}
		sess.transport.deliver(b)
		return
	}

	if d.pase != nil && d.paseAddr == peer.String() {
		d.pase.deliver(b)
		return
	}
	msg, err := message.NewMessageFromBytes(b)
	if err != nil || msg.ProtocolID() != message.SecureChannel || msg.Opcode() != message.PBKDFParamRequest {
		log.Debugf("device: drop unsecured message from %s outside a PASE exchange", peer)
		return
	}
	if d.pase != nil {
		log.Infof("device: PASE already in progress with %s, ignoring %s", d.paseAddr, peer)
		return
	}
	pt := newPeerTransport(conn, peer)
	pt.deliver(b)
	d.pase = pt
	d.paseAddr = peer.String()
	d.wg.Add(1)
	go d.runPASE(pt, d.newSessionIDLocked())
}

func (d *Device) runPASE(pt *peerTransport, sessionID types.SessionID) {
	defer d.wg.Done()
	keys, err := pase.NewResponder(pt, d.verifier, pase.WithResponderSessionID(sessionID)).EstablishSession(d.ctx)

	d.mu.Lock()
	d.pase = nil
	d.paseAddr = ""
	if err != nil {
		d.mu.Unlock()
		log.Warnf("device: PASE with %s failed: %v", pt.peer, err)
		return
	}
	transport := newPeerTransport(pt.conn, pt.peer)
	sess := &Session{
		keys:      keys,
		peer:      pt.peer,
		transport: transport,
		secure:    session.NewSecureSession(transport, keys, session.WithRole(session.RoleResponder)),
	}
	d.sessions[sessionID] = sess
	handler := d.onSession
	d.wg.Add(1)
	go d.serveSession(sess)
	d.mu.Unlock()

	log.Infof("device: PASE session %d established with %s", sessionID, pt.peer)
	if handler != nil {
		handler(sess)
	}
}

// serveSession answers the Interaction Model requests arriving on sess until
// its transport is closed. A message which fails, such as one which does
// not decrypt, is logged and the session keeps serving.
func (d *Device) serveSession(sess *Session) {
	defer d.wg.Done()
	for {
		err := d.imServer.ServeOne(sess.secure)
		if err == nil {
			continue
		}
		if sess.transport.isClosed() {
			return
		}
		log.Warnf("device: session with %s: %v", sess.peer, err)
	}
}

// newSessionIDLocked picks a non-zero session ID no current session uses
// (Matter Core 4.13.2.4).
func (d *Device) newSessionIDLocked() types.SessionID {
	for {
		id := types.NewSessionID()
		if _, used := d.sessions[id]; id != 0 && !used {
			return id
		}
	}
}

// errTransportClosed is returned by a closed peerTransport.
var errTransportClosed = errors.New("device: transport closed")

// peerTransport is the io.Transport for one peer over the device's shared
// socket: it sends to the peer, and receives what dispatch delivers until
// it is closed.
type peerTransport struct {
	conn      *net.UDPConn
	peer      *net.UDPAddr
	in        chan []byte
	closed    chan struct{}
	closeOnce sync.Once
}

func newPeerTransport(conn *net.UDPConn, peer *net.UDPAddr) *peerTransport {
	return &peerTransport{
		conn:      conn,
		peer:      peer,
		in:        make(chan []byte, peerQueueLength),
		closed:    make(chan struct{}),
		closeOnce: sync.Once{},
	}
}

func (t *peerTransport) close() {
	t.closeOnce.Do(func() { close(t.closed) })
}

func (t *peerTransport) isClosed() bool {
	select {
	case <-t.closed:
		return true
	default:
		return false
	}
}

func (t *peerTransport) deliver(b []byte) {
	select {
	case t.in <- b:
	default:
		log.Warnf("device: queue for %s full, dropping a message", t.peer)
	}
}

func (t *peerTransport) Transmit(_ context.Context, b []byte) error {
	_, err := t.conn.WriteToUDP(b, t.peer)
	return err
}

func (t *peerTransport) Receive(ctx context.Context) ([]byte, error) {
	select {
	case b := <-t.in:
		return b, nil
	case <-t.closed:
		return nil, errTransportClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
