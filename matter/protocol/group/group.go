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

// Package group implements Matter group messaging security: the keys a
// group's messages are encrypted with, derived from a group key set's
// epoch key, the group session ID which names them, the IPv6 multicast
// address of a group, and the encryption of a group message (Matter Core,
// Group Communication).
package group

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"slices"

	"github.com/cybergarage/go-matter/matter/crypto"
	"github.com/cybergarage/go-matter/matter/encoding/message"
)

const (
	// Port is the UDP port group messages are sent to, the Matter port.
	Port = 5540

	keyLength = 16
	micLength = 16

	// sessionTypeGroup is the Session Type of a group message's security
	// flags (4.4.1.3).
	sessionTypeGroup = 0x01
)

var (
	operationalKeyInfo = []byte("GroupKey v1.0")
	keyHashInfo        = []byte("GroupKeyHash")

	// ErrNotGroupMessage is returned for a message which is not a group
	// message: no group session, no source node ID or no group ID.
	ErrNotGroupMessage = errors.New("group: not a group message")
)

// OperationalKey derives the operational group key of an epoch key on a
// fabric, which encrypts the group's messages: Crypto_KDF(EpochKey,
// CompressedFabricIdentifier, "GroupKey v1.0").
func OperationalKey(epochKey []byte, compressedFabricID uint64) ([]byte, error) {
	salt := make([]byte, 8)
	binary.BigEndian.PutUint64(salt, compressedFabricID)
	return crypto.CryptoKDF(epochKey, salt, operationalKeyInfo, keyLength)
}

// SessionID derives the group session ID of an operational group key, the
// first two bytes of Crypto_KDF(OperationalGroupKey, [], "GroupKeyHash"),
// which a group message carries in its Session ID field so that a receiver
// knows which keys to try.
func SessionID(operationalKey []byte) (uint16, error) {
	hash, err := crypto.CryptoKDF(operationalKey, nil, keyHashInfo, 2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(hash), nil
}

// MulticastAddress returns the IPv6 multicast address a fabric's group
// messages are sent to, FF35:0040:FD<Fabric ID>00:<Group ID>.
func MulticastAddress(fabricID uint64, groupID uint16) net.IP {
	ip := make(net.IP, net.IPv6len)
	ip[0], ip[1], ip[2], ip[3], ip[4] = 0xFF, 0x35, 0x00, 0x40, 0xFD
	binary.BigEndian.PutUint64(ip[5:13], fabricID)
	ip[13] = 0x00
	binary.BigEndian.PutUint16(ip[14:16], groupID)
	return ip
}

// Message is a group message's header fields which say who sent it to
// which group.
type Message struct {
	Header       message.Header
	SourceNodeID uint64
	GroupID      uint16
	// Private is set when the message has the P flag: its Message
	// Counter, SourceNodeID and GroupID are obfuscated, and known only from
	// the message Open returns.
	Private bool
	// Payload is the encrypted protocol header and application payload,
	// with the MIC.
	Payload []byte
	// headerBytes is the header as received, the AAD.
	headerBytes []byte
	// packet is the message as received.
	packet []byte
}

// Parse splits a group message into its header and encrypted payload. The
// header fields of a message with privacy are obfuscated until Open.
func Parse(packet []byte) (*Message, error) {
	hdr, err := message.NewHeaderFromBytes(packet)
	if err != nil {
		return nil, err
	}
	if hdr.SecurityFlags().SessionType() != sessionTypeGroup {
		return nil, ErrNotGroupMessage
	}
	src, ok := hdr.SourceNodeID()
	if !ok {
		return nil, ErrNotGroupMessage
	}
	gid, ok := hdr.GroupID()
	if !ok {
		return nil, ErrNotGroupMessage
	}
	if hdr.SecurityFlags().HasMessageExtensions() {
		return nil, fmt.Errorf("group: message extensions are not supported")
	}
	hdrBytes, err := hdr.Bytes()
	if err != nil {
		return nil, err
	}
	if len(packet) < len(hdrBytes)+micLength {
		return nil, fmt.Errorf("group: message too short")
	}
	return &Message{
		Header:       hdr,
		SourceNodeID: uint64(src),
		GroupID:      uint16(gid),
		Private:      hdr.SecurityFlags().HasPrivacy(),
		Payload:      packet[len(hdrBytes):],
		headerBytes:  packet[:len(hdrBytes)],
		packet:       packet,
	}, nil
}

// Decrypt decrypts a message without privacy with an operational group
// key, returning the protocol header and application payload.
func (m *Message) Decrypt(operationalKey []byte) ([]byte, error) {
	if m.Private {
		return nil, fmt.Errorf("group: the message has privacy; use Open")
	}
	nonce := crypto.CryptoCCMNonce(byte(m.Header.SecurityFlags()), uint32(m.Header.MessageCounter()), m.SourceNodeID)
	return crypto.CryptoCCMDecrypt(operationalKey, nonce, m.Payload, m.headerBytes)
}

// Open decrypts the message with an operational group key, first
// deobfuscating the header of a message with privacy (4.9.3). It returns
// the message with its header fields in clear, and the protocol header and
// application payload.
func (m *Message) Open(operationalKey []byte) (*Message, []byte, error) {
	if !m.Private {
		plaintext, err := m.Decrypt(operationalKey)
		return m, plaintext, err
	}
	packet := slices.Clone(m.packet)
	if err := obfuscate(operationalKey, packet); err != nil {
		return nil, nil, err
	}
	opened, err := Parse(packet)
	if err != nil {
		return nil, nil, err
	}
	nonce := crypto.CryptoCCMNonce(byte(opened.Header.SecurityFlags()), uint32(opened.Header.MessageCounter()), opened.SourceNodeID)
	plaintext, err := crypto.CryptoCCMDecrypt(operationalKey, nonce, opened.Payload, opened.headerBytes)
	if err != nil {
		return nil, nil, err
	}
	return opened, plaintext, nil
}

// Encrypt builds a group message from sourceNodeID to groupID of payload,
// a protocol header and application payload, with an operational group
// key and the message counter of the sender.
func Encrypt(operationalKey []byte, sourceNodeID uint64, groupID uint16, counter uint32, payload []byte) ([]byte, error) {
	return encrypt(operationalKey, sourceNodeID, groupID, counter, payload, false)
}

// EncryptWithPrivacy builds a group message as Encrypt does, with the P
// flag, its Message Counter, Source Node ID and Group ID obfuscated with
// the privacy key of the operational group key (4.9.3).
func EncryptWithPrivacy(operationalKey []byte, sourceNodeID uint64, groupID uint16, counter uint32, payload []byte) ([]byte, error) {
	return encrypt(operationalKey, sourceNodeID, groupID, counter, payload, true)
}

func encrypt(operationalKey []byte, sourceNodeID uint64, groupID uint16, counter uint32, payload []byte, private bool) ([]byte, error) {
	sessionID, err := SessionID(operationalKey)
	if err != nil {
		return nil, err
	}
	secFlags := message.SecurityFlag(sessionTypeGroup)
	if private {
		secFlags |= message.PrivacyMask
	}
	hdr := message.NewHeader(
		message.WithHeaderSessionID(message.SessionID(sessionID)),
		message.WithHeaderSecurityFlags(secFlags),
		message.WithHeaderMessageCounter(message.MessageCounter(counter)),
		message.WithHeaderSourceNodeID(message.NodeID(sourceNodeID)),
		message.WithHeaderGroupID(message.GroupID(groupID)),
	)
	hdrBytes, err := hdr.Bytes()
	if err != nil {
		return nil, err
	}
	nonce := crypto.CryptoCCMNonce(byte(secFlags), counter, sourceNodeID)
	sealed, err := crypto.CryptoCCMEncrypt(operationalKey, nonce, payload, hdrBytes)
	if err != nil {
		return nil, err
	}
	packet := make([]byte, 0, len(hdrBytes)+len(sealed))
	packet = append(packet, hdrBytes...)
	packet = append(packet, sealed...)
	if private {
		if err := obfuscate(operationalKey, packet); err != nil {
			return nil, err
		}
	}
	return packet, nil
}
