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

package crypto

import (
	"bytes"
	"errors"
	"testing"
)

// TestCryptoCCMRoundtrip verifies that CryptoCCMEncrypt followed by CryptoCCMDecrypt
// recovers the original plaintext.
func TestCryptoCCMRoundtrip(t *testing.T) {
	t.Parallel()

	key := make([]byte, 16)
	nonce := make([]byte, 13)
	aad := []byte("matter-header-aad")
	plaintext := []byte("hello from the initiator")

	for i := range key {
		key[i] = byte(i + 1)
	}
	for i := range nonce {
		nonce[i] = byte(i + 0x10)
	}

	ciphertextWithTag, err := CryptoCCMEncrypt(key, nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("CryptoCCMEncrypt failed: %v", err)
	}

	if len(ciphertextWithTag) != len(plaintext)+ccmTagLen {
		t.Fatalf("expected ciphertext length %d, got %d", len(plaintext)+ccmTagLen, len(ciphertextWithTag))
	}

	decrypted, err := CryptoCCMDecrypt(key, nonce, ciphertextWithTag, aad)
	if err != nil {
		t.Fatalf("CryptoCCMDecrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted text mismatch: got %x, want %x", decrypted, plaintext)
	}
}

// TestCryptoCCMEmptyPlaintext verifies that AES-CCM works with an empty plaintext.
func TestCryptoCCMEmptyPlaintext(t *testing.T) {
	t.Parallel()

	key := bytes.Repeat([]byte{0xAA}, 16)
	nonce := bytes.Repeat([]byte{0xBB}, 13)
	aad := []byte("header")
	plaintext := []byte{}

	ciphertextWithTag, err := CryptoCCMEncrypt(key, nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("CryptoCCMEncrypt failed: %v", err)
	}

	if len(ciphertextWithTag) != ccmTagLen {
		t.Fatalf("expected only tag (%d bytes), got %d bytes", ccmTagLen, len(ciphertextWithTag))
	}

	decrypted, err := CryptoCCMDecrypt(key, nonce, ciphertextWithTag, aad)
	if err != nil {
		t.Fatalf("CryptoCCMDecrypt failed: %v", err)
	}

	if len(decrypted) != 0 {
		t.Fatalf("expected empty decrypted plaintext, got %x", decrypted)
	}
}

// TestCryptoCCMAuthFailure verifies that authentication fails when the tag is tampered with.
func TestCryptoCCMAuthFailure(t *testing.T) {
	t.Parallel()

	key := make([]byte, 16)
	nonce := make([]byte, 13)
	aad := []byte("authentic-header")
	plaintext := []byte("secret payload")

	ciphertextWithTag, err := CryptoCCMEncrypt(key, nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("CryptoCCMEncrypt failed: %v", err)
	}

	// Tamper with the last byte of the tag.
	ciphertextWithTag[len(ciphertextWithTag)-1] ^= 0xFF

	_, err = CryptoCCMDecrypt(key, nonce, ciphertextWithTag, aad)
	if !errors.Is(err, ErrCCMAuthFailed) {
		t.Fatalf("expected ErrCCMAuthFailed, got %v", err)
	}
}

// TestCryptoCCMWrongAAD verifies that authentication fails when AAD is modified.
func TestCryptoCCMWrongAAD(t *testing.T) {
	t.Parallel()

	key := make([]byte, 16)
	nonce := make([]byte, 13)
	aad := []byte("correct-header")
	plaintext := []byte("payload")

	ciphertextWithTag, err := CryptoCCMEncrypt(key, nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("CryptoCCMEncrypt failed: %v", err)
	}

	_, err = CryptoCCMDecrypt(key, nonce, ciphertextWithTag, []byte("wrong-header"))
	if !errors.Is(err, ErrCCMAuthFailed) {
		t.Fatalf("expected ErrCCMAuthFailed with wrong AAD, got %v", err)
	}
}

// TestCryptoCCMNonce verifies the nonce construction helper.
func TestCryptoCCMNonce(t *testing.T) {
	t.Parallel()

	secFlags := byte(0x00)
	msgCounter := uint32(0xDEADBEEF)
	srcNodeID := uint64(0x0102030405060708)

	nonce := CryptoCCMNonce(secFlags, msgCounter, srcNodeID)

	if len(nonce) != 13 {
		t.Fatalf("nonce length: expected 13, got %d", len(nonce))
	}
	if nonce[0] != secFlags {
		t.Errorf("nonce[0] SecurityFlags: expected 0x%02X, got 0x%02X", secFlags, nonce[0])
	}
	if nonce[1] != 0xEF || nonce[2] != 0xBE || nonce[3] != 0xAD || nonce[4] != 0xDE {
		t.Errorf("nonce[1:5] MessageCounter (LE): expected EF BE AD DE, got %X", nonce[1:5])
	}
	if nonce[5] != 0x08 || nonce[12] != 0x01 {
		t.Errorf("nonce[5:13] SourceNodeID (LE): expected 08...01, got %X", nonce[5:13])
	}
}
