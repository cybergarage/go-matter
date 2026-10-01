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
	"errors"
	"net"
	"testing"

	"github.com/cybergarage/go-matter/matter/encoding/message"
)

func TestMulticastAddress(t *testing.T) {
	got := MulticastAddress(0x1122334455667788, 0x0101)
	want := net.ParseIP("ff35:40:fd11:2233:4455:6677:8800:101")
	if !got.Equal(want) {
		t.Fatalf("MulticastAddress = %s, want %s", got, want)
	}
}

func TestEncryptDecrypt(t *testing.T) {
	epochKey := bytes.Repeat([]byte{0xD0}, 16)
	key, err := OperationalKey(epochKey, 0x87E1B004E235A130)
	if err != nil || len(key) != 16 {
		t.Fatalf("OperationalKey = (%x, %v)", key, err)
	}
	other, _ := OperationalKey(epochKey, 0x87E1B004E235A131)
	if bytes.Equal(key, other) {
		t.Fatal("the operational key does not depend on the fabric")
	}
	sid, err := SessionID(key)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte{0x01, 0x08, 0x34, 0x12, 0x01, 0x00, 0x15, 0x18}
	packet, err := Encrypt(key, 0x1B669, 0x0101, 42, payload)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := Parse(packet)
	if err != nil {
		t.Fatal(err)
	}
	if msg.SourceNodeID != 0x1B669 || msg.GroupID != 0x0101 || uint16(msg.Header.SessionID()) != sid || msg.Header.MessageCounter() != 42 {
		t.Fatalf("parsed source 0x%X group 0x%X session 0x%X counter %d", msg.SourceNodeID, msg.GroupID, msg.Header.SessionID(), msg.Header.MessageCounter())
	}
	plain, err := msg.Decrypt(key)
	if err != nil || !bytes.Equal(plain, payload) {
		t.Fatalf("Decrypt = (%x, %v), want %x", plain, err, payload)
	}
	if _, err := msg.Decrypt(other); err == nil {
		t.Fatal("another fabric's key decrypted the message")
	}
	packet[len(packet)-1] ^= 1
	if msg, err := Parse(packet); err != nil {
		t.Fatal(err)
	} else if _, err := msg.Decrypt(key); err == nil {
		t.Fatal("a corrupted message decrypted")
	}
}

func TestParseRejectsUnicast(t *testing.T) {
	hdr, err := message.NewHeader(message.WithHeaderSessionID(5), message.WithHeaderMessageCounter(1)).Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(append(hdr, make([]byte, 20)...)); !errors.Is(err, ErrNotGroupMessage) {
		t.Fatalf("Parse(unicast) = %v, want ErrNotGroupMessage", err)
	}
}

// TestOperationalKeyVector checks the derivation against the example of
// the specification, which the SDK's tests use too.
func TestOperationalKeyVector(t *testing.T) {
	epochKey := []byte{0x23, 0x5b, 0xf7, 0xe6, 0x28, 0x23, 0xd3, 0x58, 0xdc, 0xa4, 0xba, 0x50, 0xb1, 0x53, 0x5f, 0x4b}
	key, err := OperationalKey(epochKey, 0x87E1B004E235A130)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0xa6, 0xf5, 0x30, 0x6b, 0xaf, 0x6d, 0x05, 0x0a, 0xf2, 0x3b, 0xa4, 0xbd, 0x6b, 0x9d, 0xd9, 0x60}
	if !bytes.Equal(key, want) {
		t.Fatalf("OperationalKey = %x, want %x", key, want)
	}
	if sid, err := SessionID(key); err != nil || sid != 0xB9F7 {
		t.Fatalf("SessionID = (0x%04X, %v), want 0xB9F7", sid, err)
	}
}
