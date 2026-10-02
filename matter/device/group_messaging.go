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
	"errors"
	"net"
	"slices"
	"sync"

	"github.com/cybergarage/go-logger/log"
	caseprotocol "github.com/cybergarage/go-matter/matter/protocol/case"
	"github.com/cybergarage/go-matter/matter/protocol/group"
	"github.com/cybergarage/go-matter/matter/protocol/im"
	"github.com/cybergarage/go-matter/matter/protocol/session"
	"github.com/cybergarage/go-matter/matter/store"
)

var errGroupSession = errors.New("device: a group session cannot send or receive")

// groupSessionType is the Session Type of a group message's security flags
// (4.4.1.3).
const groupSessionType = 0x01

// groupSession stands for the messages of a group in access checks and
// command handlers: the fabric and group they were sent to, and the node
// which sent them. Nothing answers a group message, so it neither sends
// nor receives.
type groupSession struct {
	fabricIndex  uint8
	groupID      uint16
	sourceNodeID uint64
}

func (g *groupSession) Transmit([]byte) error            { return errGroupSession }
func (g *groupSession) Receive() ([]byte, error)         { return nil, errGroupSession }
func (g *groupSession) Transport() session.Transport     { return nil }
func (g *groupSession) SessionKeys() session.SessionKeys { return nil }

// groupPeer is a sender of group messages on a fabric, whose message
// counters are tracked to drop replays.
type groupPeer struct {
	fabricIndex uint8
	nodeID      uint64
}

// groupCounterWindow is the message counters of a group peer received
// lately: the largest one and a bitmap of the 32 before it.
type groupCounterWindow struct {
	max    uint32
	window uint32
}

// accept reports whether counter is new, and records it.
func (w *groupCounterWindow) accept(counter uint32) bool {
	switch {
	case counter > w.max:
		shift := counter - w.max
		if shift >= 32 {
			w.window = 0
		} else {
			w.window = w.window<<shift | 1<<(shift-1)
		}
		w.max = counter
		return true
	case counter == w.max:
		return false
	default:
		behind := w.max - counter
		if 32 < behind || w.window&(1<<(behind-1)) != 0 {
			return false
		}
		w.window |= 1 << (behind - 1)
		return true
	}
}

// groupMessaging receives the messages sent to the groups the device's
// endpoints are in: for each group it opens a socket bound to the group's
// multicast address on the Matter port, which only the group's messages
// reach, joins the address, decrypts the messages with the group keys
// and serves their commands.
type groupMessaging struct {
	mutex    sync.Mutex
	device   *Device
	started  bool
	conns    map[string]*net.UDPConn
	counters map[groupPeer]*groupCounterWindow
}

func newGroupMessaging(d *Device) *groupMessaging {
	return &groupMessaging{
		mutex:    sync.Mutex{},
		device:   d,
		started:  false,
		conns:    map[string]*net.UDPConn{},
		counters: map[groupPeer]*groupCounterWindow{},
	}
}

// start lets update open the sockets of the groups. The groups are read
// by update, which the device's first refresh calls: start runs with the
// device's lock held, and reading the groups takes locks which must not
// be taken under it.
func (gm *groupMessaging) start() {
	gm.mutex.Lock()
	defer gm.mutex.Unlock()
	gm.started = true
}

// stop closes the sockets of the groups.
func (gm *groupMessaging) stop() {
	gm.mutex.Lock()
	defer gm.mutex.Unlock()
	gm.started = false
	for key, conn := range gm.conns {
		_ = conn.Close()
		delete(gm.conns, key)
	}
}

func (gm *groupMessaging) serve(conn *net.UDPConn) {
	defer gm.device.wg.Done()
	buf := make([]byte, maxMessageSize)
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		gm.receive(bytes.Clone(buf[:n]))
	}
}

// joined reports whether the device listens on a group's address.
func (gm *groupMessaging) joined(ip net.IP) bool {
	gm.mutex.Lock()
	defer gm.mutex.Unlock()
	_, ok := gm.conns[ip.String()]
	return ok
}

// update listens on the multicast addresses of the groups the endpoints
// are in, and stops listening on those of the groups they left.
func (gm *groupMessaging) update() {
	want := map[string]net.IP{}
	fabrics, err := gm.device.opCreds.fabrics()
	if err != nil {
		return
	}
	for _, f := range fabrics {
		rec, err := gm.device.groupKeys.load(f.FabricIndex)
		if err != nil {
			continue
		}
		for _, g := range rec.Groups {
			ip := group.MulticastAddress(f.FabricID, g.GroupID)
			want[ip.String()] = ip
		}
	}

	gm.mutex.Lock()
	defer gm.mutex.Unlock()
	if !gm.started {
		return
	}
	for key, ip := range want {
		if _, ok := gm.conns[key]; ok {
			continue
		}
		conn, err := listenGroup(ip)
		if err != nil {
			log.Warnf("device: listen on group address %s: %v", ip, err)
			continue
		}
		gm.conns[key] = conn
		gm.device.wg.Add(1)
		go gm.serve(conn)
	}
	for key, conn := range gm.conns {
		if _, ok := want[key]; !ok {
			_ = conn.Close()
			delete(gm.conns, key)
		}
	}
}

// receive decrypts a group message with the keys of the fabrics which map
// its group to a key set whose group session ID it carries, and serves it
// on the endpoints in the group.
func (gm *groupMessaging) receive(packet []byte) {
	msg, err := group.Parse(packet)
	if err != nil {
		log.Debugf("device: drop group message: %v", err)
		return
	}
	fabrics, err := gm.device.opCreds.fabrics()
	if err != nil {
		return
	}
	for _, f := range fabrics {
		rec, err := gm.device.groupKeys.load(f.FabricIndex)
		if err != nil {
			continue
		}
		opened, plaintext, ok := decryptGroupMessage(msg, f, rec)
		if !ok {
			continue
		}
		// A message with privacy says who sent it to which group once
		// opened.
		msg = opened
		endpoints := groupEndpoints(rec, msg.GroupID)
		if len(endpoints) == 0 {
			return
		}
		if !gm.acceptCounter(groupPeer{fabricIndex: f.FabricIndex, nodeID: msg.SourceNodeID}, uint32(msg.Header.MessageCounter())) {
			log.Debugf("device: drop a replayed group message from node 0x%X", msg.SourceNodeID)
			return
		}
		sess := &groupSession{fabricIndex: f.FabricIndex, groupID: msg.GroupID, sourceNodeID: msg.SourceNodeID}
		if err := gm.device.imServer.ServeGroupMessage(sess, plaintext, endpoints); err != nil {
			log.Warnf("device: group message from node 0x%X: %v", msg.SourceNodeID, err)
		}
		return
	}
	if msg.Private {
		log.Debugf("device: no key opens the message with privacy of group session 0x%04X", uint16(msg.Header.SessionID()))
		return
	}
	log.Debugf("device: no key decrypts the message to group 0x%04X from node 0x%X", msg.GroupID, msg.SourceNodeID)
}

// decryptGroupMessage tries the epoch keys of the key sets a fabric maps
// the message's group to, those whose group session ID it carries, and
// returns the message opened, with its header in clear. The group of a
// message with privacy is known only once a key deobfuscates it, so each
// group's keys are tried, and the group the message names must be the one
// the key is for (4.9.3, 4.15.3).
func decryptGroupMessage(msg *group.Message, f store.DeviceFabricRecord, rec store.GroupKeysRecord) (*group.Message, []byte, bool) {
	cfid, err := caseprotocol.ComputeCompressedFabricID(f.RootPublicKey, f.FabricID)
	if err != nil {
		return nil, nil, false
	}
	for _, entry := range rec.KeyMap {
		if !msg.Private && entry.GroupID != msg.GroupID {
			continue
		}
		i := slices.IndexFunc(rec.KeySets, func(s store.GroupKeySet) bool { return s.GroupKeySetID == entry.GroupKeySetID })
		if i < 0 {
			continue
		}
		for _, epoch := range rec.KeySets[i].EpochKeys {
			key, err := group.OperationalKey(epoch.Key, cfid)
			if err != nil {
				continue
			}
			if sid, err := group.SessionID(key); err != nil || sid != uint16(msg.Header.SessionID()) {
				continue
			}
			if opened, plaintext, err := msg.Open(key); err == nil && opened.GroupID == entry.GroupID {
				return opened, plaintext, true
			}
		}
	}
	return nil, nil, false
}

func groupEndpoints(rec store.GroupKeysRecord, groupID uint16) []im.EndpointID {
	for _, g := range rec.Groups {
		if g.GroupID != groupID {
			continue
		}
		endpoints := make([]im.EndpointID, 0, len(g.Endpoints))
		for _, ep := range g.Endpoints {
			endpoints = append(endpoints, im.EndpointID(ep))
		}
		return endpoints
	}
	return nil
}

func (gm *groupMessaging) acceptCounter(peer groupPeer, counter uint32) bool {
	gm.mutex.Lock()
	defer gm.mutex.Unlock()
	w, ok := gm.counters[peer]
	if !ok {
		// Trust the first counter a peer sends.
		gm.counters[peer] = &groupCounterWindow{max: counter, window: 0}
		return true
	}
	return w.accept(counter)
}
