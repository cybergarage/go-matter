// Copyright (C) 2026 The go-matter Authors. Licensed under the Apache License, Version 2.0.

// Package tui implements the matterctl terminal controller. UI dependencies stay inside cmd.
package tui

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cybergarage/go-matter/matter"
	"github.com/cybergarage/go-matter/matter/cluster/descriptor"
	"github.com/cybergarage/go-matter/matter/credentials"
	"github.com/cybergarage/go-matter/matter/encoding"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	caseprotocol "github.com/cybergarage/go-matter/matter/protocol/case"
	"github.com/cybergarage/go-matter/matter/protocol/im"
	"github.com/cybergarage/go-matter/matter/store"
)

type Device struct {
	ID   uint64
	Name string
}
type Path struct {
	Endpoint  im.EndpointID
	Cluster   im.ClusterID
	Attribute im.AttributeID
	Commands  []im.CommandID
}

func (p Path) String() string {
	return fmt.Sprintf("EP %d / cluster 0x%04X / attr 0x%04X", p.Endpoint, p.Cluster, p.Attribute)
}

type Result struct {
	Message string
	Paths   []Path
}
type Backend interface {
	List() ([]Device, error)
	Inspect(context.Context, uint64) (Result, error)
	Read(context.Context, uint64, Path) (Result, error)
	Invoke(context.Context, uint64, Path, im.CommandID) (Result, error)
	Pair(context.Context, encoding.OnboardingPayload) (Result, error)
	Close() error
}

// ParsePayload deliberately rejects arbitrary characters, hides decoder errors, and
// enforces Matter 1.5 section 5.1.1.6 reserved PIN values before any transport starts.
func ParsePayload(s string) (encoding.OnboardingPayload, error) {
	s = strings.TrimSpace(s)
	var p encoding.OnboardingPayload
	var err error
	if strings.HasPrefix(s, "MT:") {
		p, err = encoding.NewQRPayloadFromString(s)
	} else {
		for _, r := range s {
			if (r < '0' || r > '9') && r != '-' && r != ' ' {
				return nil, errors.New("enter an 11/21 digit manual code or MT: QR string")
			}
		}
		p, err = encoding.NewPairingCodeFromString(s)
	}
	if err != nil || p == nil {
		return nil, errors.New("invalid onboarding payload (length/checksum/encoding)")
	}
	pin := uint32(p.Passcode())
	if p.Version() != 0 || p.CommissioningFlow() != 0 {
		return nil, errors.New("only version 0 standard commissioning is supported")
	}
	if pin == 0 || pin > 99999998 || pin == 12345678 || pin == 87654321 {
		return nil, errors.New("invalid or reserved setup PIN")
	}
	for n := uint32(11111111); n <= 88888888; n += 11111111 {
		if pin == n {
			return nil, errors.New("invalid or reserved setup PIN")
		}
	}
	return p, nil
}

// trackingStore observes best-effort library persistence without logging any material.
// A device may have joined even if local storage failed; never promise remote rollback.
type trackingStore struct {
	store.Store
	mu       sync.Mutex
	writeErr error
}

func (s *trackingStore) SaveFabric(r store.FabricRecord) error {
	err := s.Store.SaveFabric(r)
	s.record(err)
	return err
}
func (s *trackingStore) SaveCommissionee(r store.CommissioneeRecord) error {
	err := s.Store.SaveCommissionee(r)
	s.record(err)
	return err
}
func (s *trackingStore) record(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writeErr = errors.Join(s.writeErr, err)
}
func (s *trackingStore) reset()       { s.mu.Lock(); defer s.mu.Unlock(); s.writeErr = nil }
func (s *trackingStore) failed() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.writeErr != nil }

type Live struct {
	cmr     matter.Commissioner
	st      *trackingStore
	started bool
	dir     string
}

func NewLive(st store.Store) *Live {
	tracked := &trackingStore{Store: st}
	return &Live{cmr: matter.NewCommissioner(matter.WithCommissionerStore(tracked)), st: tracked}
}
func openLiveDirectory(dir string) (*Live, error) {
	b := NewLive(store.NewMemStore())
	b.dir = dir
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		return b, nil
	} else if err != nil {
		return nil, errors.New("cannot inspect store directory")
	}
	st, err := store.NewStore(dir)
	if err != nil {
		return nil, errors.New("cannot open commissioner store")
	}
	b = NewLive(st)
	b.dir = dir
	return b, nil
}
func fabricCompressedID(r store.FabricRecord) (uint64, error) {
	der := r.RootCertificate
	if block, _ := pem.Decode(der); block != nil {
		der = block.Bytes
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return 0, errors.New("cannot parse root certificate")
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return 0, errors.New("invalid root public key")
	}
	return caseprotocol.ComputeCompressedFabricID(elliptic.Marshal(pub.Curve, pub.X, pub.Y), r.FabricID)
}
func (b *Live) Overview() (FabricSummary, error) {
	r, ok, err := b.st.LoadFabric()
	if err != nil {
		return FabricSummary{}, errors.New("cannot read fabric identity; existing data will not be overwritten")
	}
	if !ok {
		return FabricSummary{}, nil
	}
	summary := FabricSummary{Present: true, FabricID: r.FabricID, AdminNodeID: r.AdminNodeID, VendorID: r.AdminVendorID}
	summary.Valid = validFabric(r) == nil
	if !summary.Valid {
		return summary, nil
	}
	compressed, err := fabricCompressedID(r)
	if err != nil {
		return summary, err
	}
	summary.CompressedFabricID = compressed
	summary.Valid = true
	ds, err := b.List()
	if err != nil {
		return summary, err
	}
	summary.Saved = len(ds)
	return summary, nil
}
func (b *Live) CreateFabric(ctx context.Context, vendor uint16) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if vendor == 0 || vendor > 0xFFF4 {
		return Result{}, errors.New("invalid administrator vendor ID")
	}
	if b.started {
		return Result{}, errors.New("commissioner already started; restart before identity initialization")
	}
	// Reopen a previously absent directory to detect identities created since startup.
	st := b.st.Store
	if b.dir != "" {
		var err error
		st, err = store.NewStore(b.dir)
		if err != nil {
			return Result{}, errors.New("cannot open store for initialization")
		}
	}
	if _, ok, err := st.LoadFabric(); err != nil || ok {
		return Result{}, errors.New("existing or unreadable fabric identity will not be overwritten")
	}
	nodes, err := st.ListCommissionees()
	if err != nil || len(nodes) != 0 {
		return Result{}, errors.New("store contains orphaned or unreadable device records; initialization refused")
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	id, err := credentials.GenerateControllerIdentity()
	if err != nil {
		return Result{}, errors.New("cannot generate controller identity")
	}
	rec := store.FabricRecord{FabricID: id.FabricID, AdminNodeID: id.NodeID, AdminVendorID: vendor, RootCertificate: id.RootCertificate, RootPrivateKey: id.RootPrivateKey, NOC: id.NOC, PrivateKey: id.PrivateKey, IPK: id.IPK, UpdatedAt: time.Now().UTC()}
	if err := validFabric(rec); err != nil {
		return Result{}, errors.New("generated identity validation failed")
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if err := store.CreateFabric(st, rec); err != nil {
		return Result{}, errors.New("identity was not initialized: existing data or atomic save failure; reload before retrying")
	}
	// Replace the unused lazy commissioner so its next Start restores the new identity.
	next := NewLive(st)
	b.cmr = next.cmr
	b.st = next.st
	return Result{Message: "FABRIC CREATED / SAVED locally. No device has been commissioned. Reloaded identity is ready for confirmed pairing."}, nil
}
func (b *Live) List() ([]Device, error) {
	records, err := b.st.ListCommissionees()
	if err != nil {
		return nil, errors.New("cannot read commissioned device records")
	}
	fabric, ok, err := b.st.LoadFabric()
	if err != nil {
		return nil, errors.New("cannot read fabric identity")
	}
	if !ok {
		if len(records) > 0 {
			return nil, errors.New("orphaned device records; fabric identity is missing")
		}
		return nil, nil
	}
	// Validate identity separately in overview/operations. Inventory uses IDs from the selected local fabric.
	compressed, err := fabricCompressedID(fabric)
	if err != nil {
		return nil, err
	}
	var ds []Device
	seen := make(map[uint64]bool)
	for _, r := range records {
		if r.FabricID != fabric.FabricID || r.CompressedFabricID != compressed {
			continue
		}
		if seen[r.NodeID] {
			return nil, errors.New("ambiguous node IDs across stored fabrics; use a single-fabric store")
		}
		seen[r.NodeID] = true
		ds = append(ds, Device{ID: r.NodeID, Name: fmt.Sprintf("Node %016X (VID %04X / PID %04X)", r.NodeID, r.VendorID, r.ProductID)})
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i].ID < ds[j].ID })
	return ds, nil
}
func (b *Live) start() error {
	if b.started {
		return nil
	}
	rec, ok, err := b.st.LoadFabric()
	if err != nil || !ok || validFabric(rec) != nil {
		return errors.New("a valid supported fabric is required; create one explicitly or check the existing store")
	}
	if err := b.cmr.Start(); err != nil {
		_ = b.cmr.Stop()
		return errors.New("cannot start commissioner; check OS transport permissions")
	}
	b.started = true
	return nil
}

// Each operation gets a fresh CASE session. Cancel closes the transport to unblock
// Node's context-free IM methods; the connection context also carries a deadline.
func (b *Live) withNode(ctx context.Context, id uint64, fn func(matter.Node) (Result, error)) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if err := b.start(); err != nil {
		return Result{}, err
	}
	n, err := b.cmr.Connect(ctx, id)
	if err != nil {
		if ctx.Err() != nil {
			return Result{}, ctx.Err()
		}
		return Result{}, errors.New("CASE connection failed; retry Reconnect / inspect")
	}
	if err := ctx.Err(); err != nil {
		_ = n.Close()
		return Result{}, err
	}
	stop := context.AfterFunc(ctx, func() { _ = n.Close() })
	defer stop()
	defer n.Close()
	result, err := fn(n)
	if ctx.Err() != nil {
		return Result{}, ctx.Err()
	}
	return result, err
}
func listIDs(n matter.Node, ep im.EndpointID, cl im.ClusterID, attr im.AttributeID) ([]uint32, error) {
	var ids []uint32
	status, err := im.ReadListAttribute(n.Session(), ep, cl, attr, func(_ tlv.Decoder, e tlv.Element) error {
		v, ok := e.Unsigned()
		if !ok || v > 0xFFFFFFFF {
			return errors.New("invalid descriptor list")
		}
		ids = append(ids, uint32(v))
		return nil
	})
	if err != nil || status != nil {
		return nil, errors.New("descriptor/global list unavailable")
	}
	return ids, nil
}
func (b *Live) Inspect(ctx context.Context, id uint64) (Result, error) {
	return b.withNode(ctx, id, func(n matter.Node) (Result, error) {
		eps, err := descriptor.PartsList(n.Session(), 0)
		if err != nil {
			return Result{}, errors.New("descriptor PartsList unavailable")
		}
		eps = append([]im.EndpointID{0}, eps...)
		out := Result{Message: "CASE succeeded; session closed after inspection. Values are not monitored."}
		seen := map[im.EndpointID]bool{}
		for _, ep := range eps {
			if seen[ep] {
				continue
			}
			seen[ep] = true
			clusters, err := descriptor.ServerList(n.Session(), ep)
			if err != nil {
				return Result{}, errors.New("descriptor ServerList unavailable")
			}
			for _, cl := range clusters {
				attrs, ae := listIDs(n, ep, cl, 0xFFFB)
				cmds, ce := listIDs(n, ep, cl, 0xFFF9)
				if ae != nil {
					out.Message += "\nSome AttributeLists unavailable."
					continue
				}
				for _, a := range attrs {
					path := Path{Endpoint: ep, Cluster: cl, Attribute: im.AttributeID(a)}
					if cl == 6 && a == 0 && ce == nil {
						for _, c := range cmds {
							if c <= 2 {
								path.Commands = append(path.Commands, im.CommandID(c))
							}
						}
					}
					out.Paths = append(out.Paths, path)
				}
			}
		}
		return out, nil
	})
}
func readable(p Path) bool {
	return p.Cluster == 6 && p.Attribute == 0 || p.Cluster == 0x28 && (p.Attribute == 1 || p.Attribute == 2 || p.Attribute == 4 || p.Attribute == 5 || p.Attribute == 8 || p.Attribute == 9)
}
func readNode(n matter.Node, p Path) (Result, error) {
	if !readable(p) {
		return Result{}, errors.New("read not implemented for this attribute in the initial TUI")
	}
	r, err := n.ReadAttribute(p.Endpoint, p.Cluster, p.Attribute)
	if err != nil || r == nil || r.Status != nil || r.Value == nil {
		return Result{}, errors.New("attribute read failed / rejected")
	}
	value := "unsupported value type"
	if v, ok := r.Value.Bool(); ok {
		value = fmt.Sprint(v)
	} else if v, ok := r.Value.Unsigned(); ok {
		value = fmt.Sprint(v)
	} else if v, ok := r.Value.UTF8(); ok {
		value = v
	}
	return Result{Message: "FRESH READ: " + p.String() + " = " + value + "\nSession closed; no subscription."}, nil
}
func (b *Live) Read(ctx context.Context, id uint64, p Path) (Result, error) {
	return b.withNode(ctx, id, func(n matter.Node) (Result, error) { return readNode(n, p) })
}
func invokeNode(n matter.Node, p Path, c im.CommandID) (Result, error) {
	if p.Cluster != 6 || p.Attribute != 0 || c > 2 {
		return Result{}, errors.New("only advertised On/Off commands are supported")
	}
	allowed := false
	for _, v := range p.Commands {
		if v == c {
			allowed = true
		}
	}
	if !allowed {
		return Result{}, errors.New("command was not advertised by this device")
	}
	r, err := n.Invoke(p.Endpoint, p.Cluster, c, nil)
	if err != nil || r == nil || !r.IsSuccess() {
		return Result{}, errors.New("invoke failed; outcome uncertain, read before retrying")
	}
	read, err := readNode(n, p)
	if err != nil {
		// The invocation succeeded; retain that outcome while labelling missing readback.
		return Result{Message: "INVOKE ACKNOWLEDGED; fresh readback FAILED. Value unknown."}, nil //nolint:nilerr
	}
	return Result{Message: "INVOKE ACKNOWLEDGED\n" + read.Message}, nil
}
func (b *Live) Invoke(ctx context.Context, id uint64, p Path, c im.CommandID) (Result, error) {
	return b.withNode(ctx, id, func(n matter.Node) (Result, error) { return invokeNode(n, p, c) })
}
func (b *Live) Pair(ctx context.Context, p encoding.OnboardingPayload) (Result, error) {
	rec, ok, err := b.st.LoadFabric()
	if err != nil || !ok || validFabric(rec) != nil {
		return Result{}, errors.New("pairing requires a valid fabric in this store; choose Create new fabric when absent")
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if err := b.start(); err != nil {
		return Result{}, err
	}
	b.st.reset()
	c, err := b.cmr.Commission(ctx, p)
	if err != nil {
		if ctx.Err() != nil {
			return Result{}, ctx.Err()
		}
		return Result{}, errors.New("pairing failed or canceled. Device outcome may be uncertain; do not automatically retry")
	}
	id, ok := c.NodeID()
	if !ok {
		return Result{}, errors.New("commissioning returned no node identity")
	}
	if b.st.failed() {
		return Result{Message: fmt.Sprintf("Device joined as %016X, but LOCAL SAVE FAILED. Do not retry pairing; restart access is not guaranteed.", id)}, nil
	}
	records, err := b.st.ListCommissionees()
	if err == nil {
		for _, r := range records {
			if r.NodeID == uint64(id) {
				return Result{Message: fmt.Sprintf("PAIRING COMPLETE / SAVED: node %016X. Reload devices.", id)}, nil
			}
		}
	}
	return Result{Message: "Device joined, but record verification failed. Restart access is not guaranteed."}, nil
}
func (b *Live) Close() error {
	if b.started {
		return b.cmr.Stop()
	}
	return nil
}

// Demo is explicitly fictional, keeps no credentials, and never opens a transport.
type Demo struct {
	on     bool
	paired bool
}

func (b *Demo) List() ([]Device, error) {
	ds := []Device{{ID: 0x101, Name: "Fictional desk light"}}
	if b.paired {
		ds = append(ds, Device{ID: 0x102, Name: "Fictional paired light"})
	}
	return ds, nil
}
func (b *Demo) Inspect(ctx context.Context, _ uint64) (Result, error) {
	return Result{Message: "OFFLINE FIXTURE: simulated inventory; no session or network.", Paths: []Path{{Endpoint: 1, Cluster: 6, Attribute: 0, Commands: []im.CommandID{0, 1, 2}}, {Endpoint: 0, Cluster: 0x28, Attribute: 1}}}, ctx.Err()
}
func (b *Demo) Read(ctx context.Context, _ uint64, p Path) (Result, error) {
	value := fmt.Sprint(b.on)
	if p.Cluster == 0x28 {
		value = "Fictional vendor"
	}
	return Result{Message: fmt.Sprintf("OFFLINE FIXTURE / FRESH READ: %s = %s", p.String(), value)}, ctx.Err()
}
func (b *Demo) Invoke(ctx context.Context, id uint64, p Path, c im.CommandID) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	switch c {
	case 0:
		b.on = false
	case 1:
		b.on = true
	case 2:
		b.on = !b.on
	}
	r, e := b.Read(ctx, id, p)
	r.Message = "OFFLINE FIXTURE / INVOKE ACKNOWLEDGED\n" + r.Message
	return r, e
}
func (b *Demo) Pair(ctx context.Context, _ encoding.OnboardingPayload) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if b.paired {
		return Result{}, errors.New("fixture already paired; duplicate rejected")
	}
	b.paired = true
	return Result{Message: "OFFLINE FIXTURE / PAIRING COMPLETE: no real credential or device changed."}, nil
}
func (*Demo) Close() error { return nil }
