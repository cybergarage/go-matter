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
	"time"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter/credentials"
	"github.com/cybergarage/go-matter/matter/crypto"
	"github.com/cybergarage/go-matter/matter/encoding/message"
	"github.com/cybergarage/go-matter/matter/mdns"
	caseprotocol "github.com/cybergarage/go-matter/matter/protocol/case"
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

// Session is a secure session a Device has established with a peer, with
// PASE or CASE. The device serves the Interaction Model on it.
type Session struct {
	keys      session.SessionKeys
	peer      *net.UDPAddr
	transport *peerTransport
	secure    session.SecureSession
	isCASE    bool
	// fabricIndex and peerNodeID are guarded by the device's lock: a
	// PASE session is bound to the fabric AddNOC adds over it.
	fabricIndex uint8
	peerNodeID  uint64
	peerCATs    []uint32
}

// Keys returns the session's keys.
func (s *Session) Keys() session.SessionKeys {
	return s.keys
}

// Peer returns the address the session was established from.
func (s *Session) Peer() net.Addr {
	return s.peer
}

// IsCASE reports whether the session was established with CASE rather
// than PASE.
func (s *Session) IsCASE() bool {
	return s.isCASE
}

// PeerNodeID returns the peer's operational node ID for a CASE session,
// and 0 for a PASE session.
func (s *Session) PeerNodeID() uint64 {
	return s.peerNodeID
}

// sessionInfo is what a cluster needs to know about the session a request
// arrived on.
type sessionInfo struct {
	// known reports whether the session is one the device established.
	known  bool
	isCASE bool
	// fabricIndex is the accessing fabric: the CASE session's, the one a
	// PASE session was bound to by AddNOC, or 0.
	fabricIndex uint8
	// peerNodeID and peerCATs are the CASE peer's subject.
	peerNodeID uint64
	peerCATs   []uint32
}

// sessionLookup returns what the device knows about a session.
type sessionLookup func(im.SecureSession) sessionInfo

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
// time a peer establishes a PASE or CASE session.
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

	// discriminator is the device's own, which a basic window advertises.
	discriminator uint16
	// window is the commissioning window, and initialWindowTimeout how
	// long the one opened at Start lasts.
	window               commissioningWindow
	initialWindowTimeout time.Duration
	// now and timer are the clock of the commissioning window and the
	// fail-safe; tests replace them.
	now   func() time.Time
	timer timerFunc

	conn   *net.UDPConn
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	// pase is the unsecured PASE exchange in progress, keyed by the
	// initiator's address; a device runs one at a time.
	pase     *peerTransport
	paseAddr string
	// cases are the unsecured CASE exchanges in progress, by the
	// initiator's address.
	cases    map[string]*peerTransport
	sessions map[types.SessionID]*Session
	opCreds  *operationalCredentials
	// descriptors serves the Descriptor cluster of each endpoint.
	descriptors *descriptors
	// diagnostics serves the General Diagnostics cluster.
	diagnostics *generalDiagnostics
	// groupKeys serves the Group Key Management cluster, and keeps the
	// groups the application endpoints join.
	groupKeys *groupKeyManagement
	// fabricRemovedHandlers are the application clusters' handlers of
	// RemoveFabric.
	fabricRemovedHandlers []func(fabricIndex uint8)
	// refresh asks the advertising loop to republish the operational
	// services, which it does until refreshDone is closed.
	refresh     chan struct{}
	refreshDone chan struct{}
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
		cases:       map[string]*peerTransport{},
		sessions:    map[types.SessionID]*Session{},
		opCreds:     nil,
		descriptors: nil,
		diagnostics: nil,
		groupKeys:   nil,

		fabricRemovedHandlers: nil,
		refresh:               make(chan struct{}, 1),
		refreshDone:           nil,

		supportedFabrics: DefaultSupportedFabrics,

		window:               commissioningWindow{open: false, stop: nil, generation: 0, failures: 0, commissioner: nil},
		discriminator:        0,
		initialWindowTimeout: DefaultCommissioningTimeout,
		now:                  time.Now,
		timer:                realTimer,
	}
	d.diagnostics = newGeneralDiagnostics(func() time.Time { return d.now() })
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
	d.discriminator = d.service.Discriminator
	d.failSafe = newFailSafe(d.store)
	d.failSafe.now = d.now
	d.failSafe.timer = d.timer
	d.failSafe.onExpire = d.failSafeExpired
	d.failSafe.onRollback = func(fabricIndex uint8) {
		if fabricIndex != 0 {
			d.unbindFabric(fabricIndex)
		}
		// The operational services follow the fabrics as they were,
		// such as a node ID an UpdateNOC changed.
		d.requestRefresh()
	}
	gc := newGeneralCommissioning(d.failSafe, d.lookupSession)
	gc.onComplete = d.commissioningCompleted
	gc.register(d.imServer)
	bi := newBasicInformation(d.service.VendorID, d.service.ProductID, d.service.DeviceName, d.service.Hostname)
	bi.register(d.imServer)
	d.opCreds = newOperationalCredentials(d.store, d.failSafe, d.attestation, d.supportedFabrics)
	d.opCreds.lookup = d.lookupSession
	d.opCreds.onFabricRemoved = d.fabricRemoved
	d.imServer.SetAccessChecker(d.checkAccess)
	d.opCreds.onFabricAdded = func(sec im.SecureSession, fabricIndex uint8) {
		d.bindFabric(sec, fabricIndex)
		d.requestRefresh()
	}
	d.opCreds.onFabricUpdated = func(uint8) { d.requestRefresh() }
	d.opCreds.register(d.imServer)
	(&accessControl{oc: d.opCreds}).register(d.imServer)
	d.groupKeys = &groupKeyManagement{oc: d.opCreds}
	d.groupKeys.register(d.imServer)
	d.diagnostics.register(d.imServer)
	(&administratorCommissioning{device: d}).register(d.imServer)
	d.descriptors = newDescriptors(d.imServer)
	d.descriptors.add(rootEndpoint, RootNodeDeviceType)
	return d, nil
}

// sessionFor returns the Session whose secure session is sec.
func (d *Device) sessionForLocked(sec im.SecureSession) *Session {
	for _, sess := range d.sessions {
		if sess.secure == sec {
			return sess
		}
	}
	return nil
}

// lookupSession tells the clusters whether a request arrived over CASE,
// and on which fabric.
func (d *Device) lookupSession(sec im.SecureSession) sessionInfo {
	d.mu.Lock()
	defer d.mu.Unlock()
	sess := d.sessionForLocked(sec)
	if sess == nil {
		return sessionInfo{known: false, isCASE: false, fabricIndex: 0, peerNodeID: 0, peerCATs: nil}
	}
	return sessionInfo{known: true, isCASE: sess.isCASE, fabricIndex: sess.fabricIndex, peerNodeID: sess.peerNodeID, peerCATs: sess.peerCATs}
}

// bindFabric binds the PASE session AddNOC arrived on to the fabric it
// added, so the commissioner can go on arming the fail-safe over it
// (11.18.6.8).
func (d *Device) bindFabric(sec im.SecureSession, fabricIndex uint8) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if sess := d.sessionForLocked(sec); sess != nil && !sess.isCASE {
		sess.fabricIndex = fabricIndex
	}
}

// unbindFabric undoes what a fabric the fail-safe rolled back left behind:
// the PASE session bound to it returns to no fabric, and the CASE sessions
// on it are closed. It is called with the fail-safe's lock held.
func (d *Device) unbindFabric(fabricIndex uint8) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for id, sess := range d.sessions {
		if sess.fabricIndex != fabricIndex {
			continue
		}
		if !sess.isCASE {
			sess.fabricIndex = 0
			continue
		}
		log.Infof("device: closing CASE session %d with %s: fabric %d was rolled back", id, sess.peer, fabricIndex)
		sess.transport.close()
		delete(d.sessions, id)
	}
}

// Start listens on the configured address. A device on no fabric opens its
// commissioning window, publishing the commissionable service if an
// Advertiser was given; a device on fabrics publishes their operational
// services, and becomes commissionable only when OpenCommissioningWindow
// is called.
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
	fabrics, err := d.store.ListDeviceFabrics()
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("device: list the fabrics: %w", err)
	}
	if len(fabrics) == 0 {
		if err := d.openWindowLocked(d.initialWindowTimeout, d.basicOpeningLocked(0, 0)); err != nil {
			_ = conn.Close()
			return err
		}
	}
	d.diagnostics.boot(d.store)
	d.conn = conn
	d.ctx, d.cancel = context.WithCancel(context.Background())
	d.wg.Add(1)
	go d.serve(conn)
	d.refreshDone = make(chan struct{})
	go d.advertiseOperational(d.ctx, d.refreshDone)
	d.requestRefresh()
	return nil
}

// requestRefresh asks for the operational services to be republished, as
// the fabrics changed. It never blocks, so it can be called with locks
// held.
func (d *Device) requestRefresh() {
	select {
	case d.refresh <- struct{}{}:
	default:
	}
}

// advertiseOperational publishes an operational service for each fabric
// the device is on, each time requestRefresh asks, until ctx ends.
func (d *Device) advertiseOperational(ctx context.Context, done chan struct{}) {
	defer close(done)
	for {
		select {
		case <-ctx.Done():
			return
		case <-d.refresh:
		}
		if d.advertiser == nil {
			continue
		}
		svcs, err := d.operationalServices()
		if err != nil {
			log.Errorf("device: list the operational services: %v", err)
			continue
		}
		if err := d.advertiser.AdvertiseOperational(svcs); err != nil {
			log.Errorf("device: advertise the operational services: %v", err)
		}
	}
}

// operationalServices returns the operational service of each fabric the
// device is on, the one added under the fail-safe included.
func (d *Device) operationalServices() ([]OperationalService, error) {
	fabrics, err := d.opCreds.fabrics()
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	service := d.service
	d.mu.Unlock()
	svcs := make([]OperationalService, 0, len(fabrics))
	for _, f := range fabrics {
		cfid, err := caseprotocol.ComputeCompressedFabricID(f.RootPublicKey, f.FabricID)
		if err != nil {
			log.Errorf("device: fabric %d: %v", f.FabricIndex, err)
			continue
		}
		svcs = append(svcs, OperationalService{
			CompressedFabricID:     cfid,
			NodeID:                 f.NodeID,
			Hostname:               service.Hostname,
			Port:                   service.Port,
			SessionIdleInterval:    service.SessionIdleInterval,
			SessionActiveInterval:  service.SessionActiveInterval,
			SessionActiveThreshold: service.SessionActiveThreshold,
		})
	}
	return svcs, nil
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
	d.window.open = false
	d.window.commissioner = nil
	d.stopWindowTimerLocked()
	for id, sess := range d.sessions {
		sess.transport.close()
		delete(d.sessions, id)
	}
	refreshDone := d.refreshDone
	d.mu.Unlock()
	d.failSafe.close()
	<-refreshDone

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

// dispatch routes one datagram: an unsecured message to the PASE or CASE
// exchange with its sender, starting one on a PBKDFParamRequest or a
// Sigma1, and a secured message to the session its session ID names.
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

	addr := peer.String()
	if ex, ok := d.cases[addr]; ok {
		ex.deliver(b)
		return
	}
	if d.pase != nil && d.paseAddr == addr {
		d.pase.deliver(b)
		return
	}
	msg, err := message.NewMessageFromBytes(b)
	if err != nil || msg.ProtocolID() != message.SecureChannel {
		log.Debugf("device: drop unsecured message from %s outside a session establishment", peer)
		return
	}
	switch msg.Opcode() {
	case message.PBKDFParamRequest:
		d.startPASELocked(conn, peer, b)
	case message.CASESigma1:
		pt := newPeerTransport(conn, peer)
		pt.deliver(b)
		d.cases[addr] = pt
		d.wg.Add(1)
		go d.runCASE(pt, d.newSessionIDLocked())
	default:
		log.Debugf("device: drop unsecured opcode 0x%02X from %s outside a session establishment", uint8(msg.Opcode()), peer)
	}
}

func (d *Device) startPASELocked(conn *net.UDPConn, peer *net.UDPAddr, b []byte) {
	if !d.acceptsPASELocked() {
		log.Debugf("device: the commissioning window is closed or in use, ignoring PASE from %s", peer)
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
	go d.runPASE(pt, d.newSessionIDLocked(), d.paseVerifierLocked())
}

func (d *Device) runPASE(pt *peerTransport, sessionID types.SessionID, verifier pase.Verifier) {
	defer d.wg.Done()
	// The session is set up before the responder reports success, since
	// the commissioner sends its first request on it right away.
	var sess *Session
	established := func(keys pase.SessionKeys) {
		d.mu.Lock()
		if d.conn != nil {
			sess = d.addSessionLocked(pt, sessionID, keys, false, 0, 0, nil)
			d.commissioningStartedLocked(sess)
		}
		d.mu.Unlock()
		// The fail-safe guards the commissioning from the start, so a
		// commissioner which goes away frees the window (11.10.6.2.1).
		if sess != nil && !d.failSafe.isArmed() {
			if code := d.failSafe.arm(0, PASEFailSafeExpiry); code != CommissioningOK {
				log.Warnf("device: arm the fail-safe for PASE: %d", code)
			}
		}
	}
	_, err := pase.NewResponder(pt, verifier,
		pase.WithResponderSessionID(sessionID),
		pase.WithResponderEstablishedHandler(established),
	).EstablishSession(d.ctx)

	d.mu.Lock()
	d.pase = nil
	d.paseAddr = ""
	if d.conn == nil {
		// The device stopped during the exchange.
		d.mu.Unlock()
		return
	}
	if err != nil {
		log.Warnf("device: PASE with %s failed: %v", pt.peer, err)
		if sess != nil {
			d.closeSessionLocked(sess)
		}
		d.failedAttemptLocked("PASE failed")
		d.mu.Unlock()
		return
	}
	d.mu.Unlock()

	log.Infof("device: PASE session %d established with %s", sessionID, pt.peer)
	d.notifySession(sess)
}

func (d *Device) runCASE(pt *peerTransport, sessionID types.SessionID) {
	defer d.wg.Done()
	var sess *Session
	established := func(es *caseprotocol.ResponderSession) {
		d.mu.Lock()
		defer d.mu.Unlock()
		if d.conn != nil {
			sess = d.addSessionLocked(pt, sessionID, es.Keys, true, es.FabricIndex, es.PeerNodeID, es.PeerCATs)
		}
	}
	responder := caseprotocol.NewResponder(pt, d.opCreds.responderFabrics,
		caseprotocol.WithResponderSessionID(sessionID),
		caseprotocol.WithResponderEstablishedHandler(established),
	)
	es, err := responder.EstablishSession(d.ctx)

	d.mu.Lock()
	addr := pt.peer.String()
	if d.cases[addr] == pt {
		delete(d.cases, addr)
	}
	if d.conn == nil {
		// The device stopped during the exchange.
		d.mu.Unlock()
		return
	}
	if err != nil {
		if sess != nil {
			d.closeSessionLocked(sess)
		}
		d.mu.Unlock()
		log.Warnf("device: CASE with %s failed: %v", pt.peer, err)
		return
	}
	d.mu.Unlock()

	log.Infof("device: CASE session %d established with node 0x%016X on fabric %d at %s", sessionID, es.PeerNodeID, es.FabricIndex, pt.peer)
	d.notifySession(sess)
}

// addSessionLocked registers a newly established session and starts
// serving the Interaction Model on it.
func (d *Device) addSessionLocked(pt *peerTransport, sessionID types.SessionID, keys session.SessionKeys, isCASE bool, fabricIndex uint8, peerNodeID uint64, peerCATs []uint32) *Session {
	transport := newPeerTransport(pt.conn, pt.peer)
	sess := &Session{
		keys:        keys,
		peer:        pt.peer,
		transport:   transport,
		secure:      session.NewSecureSession(transport, keys, session.WithRole(session.RoleResponder)),
		isCASE:      isCASE,
		fabricIndex: fabricIndex,
		peerNodeID:  peerNodeID,
		peerCATs:    peerCATs,
	}
	d.sessions[sessionID] = sess
	d.wg.Add(1)
	go d.serveSession(sess)
	return sess
}

func (d *Device) notifySession(sess *Session) {
	d.mu.Lock()
	handler := d.onSession
	d.mu.Unlock()
	if handler != nil {
		handler(sess)
	}
}

// serveSession answers the Interaction Model requests arriving on sess until
// its transport is closed. A message which fails, such as one which does
// not decrypt, is logged and the session keeps serving.
func (d *Device) serveSession(sess *Session) {
	defer d.wg.Done()
	// A subscription lives no longer than its session (8.5).
	defer d.imServer.EndSession(sess.secure)
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
