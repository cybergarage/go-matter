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
	"encoding/binary"
	"fmt"

	"github.com/cybergarage/go-matter/matter/crypto"
	"github.com/cybergarage/go-matter/matter/encoding/message"
)

// Message privacy (4.9.3. Privacy Processing): a message whose security
// flags have the P flag carries its Message Counter, Source Node ID and
// Destination fields obfuscated, so that an observer cannot follow who
// sends to which group. They are AES-CTR encrypted with the privacy key of
// the operational group key, under a nonce made of the Session ID and part
// of the MIC, after the payload is encrypted with the header in clear as
// its AAD.
const (
	// privacyHeaderOffset is where the obfuscated fields start: after the
	// Message Flags, Session ID and Security Flags.
	privacyHeaderOffset = 4
	// privacyNonceMICOffset and privacyNonceMICLength select the part of
	// the MIC the privacy nonce takes.
	privacyNonceMICOffset = 5
	privacyNonceMICLength = 11

	messageCounterLength = 4
	nodeIDLength         = 8
	groupIDLength        = 2
)

var privacyKeyInfo = []byte("PrivacyKey")

// PrivacyKey derives the privacy key of an operational group key, which
// obfuscates the header of its messages: Crypto_KDF(OperationalGroupKey,
// [], "PrivacyKey").
func PrivacyKey(operationalKey []byte) ([]byte, error) {
	return crypto.CryptoKDF(operationalKey, nil, privacyKeyInfo, keyLength)
}

// privacyHeaderEnd returns where the obfuscated fields of packet end: the
// Message Counter, then the Source Node ID and the Destination Node or
// Group ID its Message Flags say it has.
func privacyHeaderEnd(packet []byte) (int, error) {
	if len(packet) < privacyHeaderOffset {
		return 0, fmt.Errorf("group: message too short")
	}
	flags := message.Flag(packet[0])
	end := privacyHeaderOffset + messageCounterLength
	if flags&message.SourceNodeIDPresentFlag != 0 {
		end += nodeIDLength
	}
	switch flags & message.DSIZMask {
	case message.DestinationNodeIDPresentFlag:
		end += nodeIDLength
	case message.GroupIDPresentFlag:
		end += groupIDLength
	}
	if len(packet) < end+micLength {
		return 0, fmt.Errorf("group: message too short")
	}
	return end, nil
}

// obfuscate obfuscates, or deobfuscates, the header fields of packet in
// place with the privacy key of an operational group key: AES-CTR as in
// AES-CCM, under the nonce Session ID (big-endian) || MIC[5..15].
func obfuscate(operationalKey, packet []byte) error {
	end, err := privacyHeaderEnd(packet)
	if err != nil {
		return err
	}
	key, err := PrivacyKey(operationalKey)
	if err != nil {
		return err
	}
	mic := packet[len(packet)-micLength:]
	nonce := make([]byte, 0, 2+privacyNonceMICLength)
	nonce = binary.BigEndian.AppendUint16(nonce, binary.LittleEndian.Uint16(packet[1:3]))
	nonce = append(nonce, mic[privacyNonceMICOffset:privacyNonceMICOffset+privacyNonceMICLength]...)
	// AES-CCM without AAD encrypts with the AES-CTR keystream; the tag it
	// adds is not used.
	stream, err := crypto.CryptoCCMEncrypt(key, nonce, packet[privacyHeaderOffset:end], nil)
	if err != nil {
		return err
	}
	copy(packet[privacyHeaderOffset:end], stream[:end-privacyHeaderOffset])
	return nil
}
