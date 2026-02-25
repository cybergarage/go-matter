// Copyright (C) 2025 The go-matter Authors. All rights reserved.
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

package crypto

import (
	"testing"
)

func TestCryptoDRBG_Length(t *testing.T) {
	lengths := []int{1, 16, 32, 64, 128, 256, 1024, 2048}
	for _, l := range lengths {
		out := CryptoDRBG(l)
		if out == nil {
			t.Errorf("Crypto_DRBG(%d) returned nil", l)
			continue
		}
		if len(out) != l {
			t.Errorf("Crypto_DRBG(%d) returned length %d, want %d", l, len(out), l)
		}
	}
}

func TestCryptoHash_Length(t *testing.T) {
	messages := [][]byte{
		{},
		[]byte("a"),
		[]byte("The quick brown fox jumps over the lazy dog"),
		make([]byte, 1024),
	}
	for i, msg := range messages {
		hash := CryptoHash(msg)
		if hash == nil {
			t.Errorf("CryptoHash(%d) returned nil", i)
			continue
		}
		if len(hash) != CryptoHashLenBytes {
			t.Errorf("CryptoHash(%d) returned length %d, want %d", i, len(hash), CryptoHashLenBytes)
		}
	}
}

func TestCryptoHMAC_Length(t *testing.T) {
	keys := [][]byte{
		[]byte("key"),
		[]byte("anotherkey"),
		[]byte(""),
	}
	messages := [][]byte{
		[]byte("message"),
		[]byte("The quick brown fox jumps over the lazy dog"),
		[]byte(""),
	}
	for i, key := range keys {
		for j, msg := range messages {
			hmac := CryptoHMAC(key, msg)
			if hmac == nil {
				t.Errorf("CryptoHMAC(%d, %d) returned nil", i, j)
				continue
			}
			if len(hmac) != CryptoHashLenBytes {
				t.Errorf("CryptoHMAC(%d, %d) returned length %d, want %d", i, j, len(hmac), CryptoHashLenBytes)
			}
		}
	}
}

func TestCryptoPBKDF_Length(t *testing.T) {
	passwords := [][]byte{
		[]byte("password"),
		[]byte("longerpassword123"),
		[]byte(""),
	}
	salts := [][]byte{
		[]byte("salt"),
		[]byte("diffsalt"),
		[]byte(""),
	}
	lengths := []int{1, 16, 32, 64, 128, 256}
	iterations := 1000

	for _, pw := range passwords {
		for _, salt := range salts {
			for _, l := range lengths {
				out, err := CryptoPBKDF(pw, salt, iterations, l)
				if err != nil {
					t.Errorf("CryptoPBKDF(%q, %q, %d, %d) returned error: %v", pw, salt, iterations, l, err)
					continue
				}
				if len(out) != l {
					t.Errorf("CryptoPBKDF(%q, %q, %d, %d) returned length %d, want %d", pw, salt, iterations, l, len(out), l)
				}
			}
		}
	}
}
