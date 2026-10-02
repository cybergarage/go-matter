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
	"bytes"
	"testing"
)

// The "private group message" vector of the Matter SDK's
// src/transport/tests/TestSessionManagerDispatch.cpp: an empty message
// from node 1 to group 2, counter 0x12345679, with privacy. (The vector's
// sourceNodeId field says 2; its header, which the MIC covers, carries 1.)
var (
	privateVectorKey        = []byte("\xca\x92\xd7\xa0\x94\x2d\x1a\x51\x1a\x0e\x26\xad\x07\x4f\x4c\x2f")
	privateVectorPrivacyKey = []byte("\xbf\xe9\xda\x01\x6a\x76\x53\x65\xf2\xdd\x97\xa9\xf9\x39\xe4\x25")
	privateVectorPayload    = []byte("\x01\x64\xee\x0e\x20\x7d")
	// privateVectorPacket is the message as sent: the payload encrypted
	// with the header in clear, then the header obfuscated.
	privateVectorPacket = []byte("\x06\x7d\xdb\x81\xd9\x26\xaf\xce\x24\xc8\xa0\x98\x1b\xdd\x44\xf4\xe7\x30\x2b\x2f\x91\x5a\x66\xc9" +
		"\x59\x62\x90\xeb\xe4\x40\x82\x17\xb3\xc0\xc9\x21\xa2\xfc\xa4\xe1")
)

func TestPrivacyKey(t *testing.T) {
	key, err := PrivacyKey(privateVectorKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key, privateVectorPrivacyKey) {
		t.Fatalf("PrivacyKey = %X, want %X", key, privateVectorPrivacyKey)
	}
}

func TestEncryptWithPrivacy(t *testing.T) {
	packet, err := EncryptWithPrivacy(privateVectorKey, 1, 2, 0x12345679, privateVectorPayload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(packet, privateVectorPacket) {
		t.Fatalf("EncryptWithPrivacy =\n%X, want\n%X", packet, privateVectorPacket)
	}
}

func TestOpenPrivateMessage(t *testing.T) {
	msg, err := Parse(bytes.Clone(privateVectorPacket))
	if err != nil {
		t.Fatal(err)
	}
	if !msg.Private {
		t.Fatal("the message is not private")
	}
	if _, err := msg.Decrypt(privateVectorKey); err == nil {
		t.Fatal("Decrypt opened a message with privacy")
	}
	opened, plaintext, err := msg.Open(privateVectorKey)
	if err != nil {
		t.Fatal(err)
	}
	if opened.SourceNodeID != 1 || opened.GroupID != 2 || uint32(opened.Header.MessageCounter()) != 0x12345679 {
		t.Fatalf("opened node 0x%X to group %d, counter 0x%X; want node 1 to group 2, counter 0x12345679", opened.SourceNodeID, opened.GroupID, uint32(opened.Header.MessageCounter()))
	}
	if !bytes.Equal(plaintext, privateVectorPayload) {
		t.Fatalf("plaintext = %X, want %X", plaintext, privateVectorPayload)
	}
	// Another group's key does not open it.
	other := bytes.Clone(privateVectorKey)
	other[0] ^= 1
	if _, _, err := msg.Open(other); err == nil {
		t.Fatal("another key opened the message")
	}
	// A message without privacy opens as it decrypts.
	clearPacket, err := Encrypt(privateVectorKey, 1, 2, 0x1234567A, privateVectorPayload)
	if err != nil {
		t.Fatal(err)
	}
	m, err := Parse(clearPacket)
	if err != nil || m.Private {
		t.Fatal(m, err)
	}
	if opened, plaintext, err := m.Open(privateVectorKey); err != nil || opened != m || !bytes.Equal(plaintext, privateVectorPayload) {
		t.Fatalf("Open of a message without privacy = (%v, %X, %v)", opened, plaintext, err)
	}
}
