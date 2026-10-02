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

package group

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"sync"

	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	"github.com/cybergarage/go-matter/matter/protocol/im"
)

// Sender sends the messages of a node to the groups of its fabric: it
// encrypts each with a group key set's epoch key and sends it to the
// group's IPv6 multicast address on the Matter port. A group message asks
// for no answer, so a Sender learns nothing of who received it.
type Sender struct {
	mutex              sync.Mutex
	fabricID           uint64
	compressedFabricID uint64
	sourceNodeID       uint64
	nextCounter        func() (uint32, error)
	transmit           func(addr *net.UDPAddr, packet []byte) error
	privacy            bool
}

// SenderOption configures a Sender.
type SenderOption func(*Sender)

// WithCounter sets where the group message counter comes from, such as a
// store.PersistentCounter's Next. Receivers drop a message whose counter
// they have seen, so the counter must go on across restarts; by default a
// Sender starts it at a random value, which only a long-lived sender can
// rely on.
func WithCounter(next func() (uint32, error)) SenderOption {
	return func(s *Sender) {
		s.nextCounter = next
	}
}

// WithoutPrivacy makes a Sender send its messages without privacy, with
// the Message Counter, Source Node ID and Group ID in clear, for receivers
// which do not deobfuscate them. By default a Sender sends them with
// privacy, as the Matter SDK does (4.9.3).
func WithoutPrivacy() SenderOption {
	return func(s *Sender) {
		s.privacy = false
	}
}

// WithTransmitter sets how a Sender sends an encrypted group message to a
// group's address, instead of over UDP multicast on every interface.
func WithTransmitter(transmit func(addr *net.UDPAddr, packet []byte) error) SenderOption {
	return func(s *Sender) {
		s.transmit = transmit
	}
}

// NewSender returns a Sender for node sourceNodeID on the fabric
// fabricID, whose compressed fabric ID the group keys are derived with.
func NewSender(fabricID, compressedFabricID, sourceNodeID uint64, opts ...SenderOption) (*Sender, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, err
	}
	counter := binary.LittleEndian.Uint32(b[:]) >> 4 // leaves room to count up
	s := &Sender{
		mutex:              sync.Mutex{},
		fabricID:           fabricID,
		compressedFabricID: compressedFabricID,
		sourceNodeID:       sourceNodeID,
		nextCounter: func() (uint32, error) {
			counter++
			return counter, nil
		},
		transmit: transmitMulticast,
		privacy:  true,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

// Send encrypts message, a protocol header and its application payload,
// with epochKey, the current epoch key of the key set the group is mapped
// to, and sends it to the group.
func (s *Sender) Send(groupID uint16, epochKey []byte, message []byte) error {
	if groupID == 0 {
		return errors.New("group: group 0 is no group")
	}
	key, err := OperationalKey(epochKey, s.compressedFabricID)
	if err != nil {
		return err
	}
	s.mutex.Lock()
	counter, err := s.nextCounter()
	s.mutex.Unlock()
	if err != nil {
		return err
	}
	encrypt := EncryptWithPrivacy
	if !s.privacy {
		encrypt = Encrypt
	}
	packet, err := encrypt(key, s.sourceNodeID, groupID, counter, message)
	if err != nil {
		return err
	}
	return s.transmit(&net.UDPAddr{IP: MulticastAddress(s.fabricID, groupID), Port: Port, Zone: ""}, packet)
}

// Invoke sends a command to a group, to run on every endpoint of the
// group's members which serves it. commandFields is built as for
// im.Invoke.
func (s *Sender) Invoke(groupID uint16, epochKey []byte, clusterID im.ClusterID, commandID im.CommandID, commandFields []byte) error {
	msg, err := im.GroupInvokeMessage(clusterID, commandID, commandFields)
	if err != nil {
		return err
	}
	return s.Send(groupID, epochKey, msg)
}

// WriteAttribute writes an attribute on every endpoint of the group's
// members which serves it. encodeData puts the Data, tagged
// ContextTag(2), as for im.WriteAttribute.
func (s *Sender) WriteAttribute(groupID uint16, epochKey []byte, clusterID im.ClusterID, attributeID im.AttributeID, encodeData func(enc tlv.Encoder) error) error {
	msg, err := im.GroupWriteMessage(clusterID, attributeID, encodeData)
	if err != nil {
		return err
	}
	return s.Send(groupID, epochKey, msg)
}
