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
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// ccmNonceLen is the nonce length for AES-128-CCM as specified by Matter (13 bytes).
	// 4.7. Encryption.
	ccmNonceLen = 13
	// ccmTagLen is the authentication tag (MIC) length for AES-128-CCM as specified by Matter (16 bytes).
	// 4.7. Encryption.
	ccmTagLen = 16
	// ccmL is the CCM length field size (L=2, so maximum plaintext length = 2^16-1 bytes).
	ccmL = 2
	// ccmBlockSize is the AES block size (16 bytes).
	ccmBlockSize = aes.BlockSize
)

// ErrCCMAuthFailed is returned when AES-CCM authentication verification fails.
var ErrCCMAuthFailed = errors.New("AES-CCM: authentication failed")

// CryptoCCMEncrypt encrypts plaintext and produces an authentication tag using AES-128-CCM.
// Returns ciphertext with the 16-byte MIC tag appended: ciphertext || tag.
// key must be 16 bytes; nonce must be 13 bytes.
// 4.7. Encryption.
func CryptoCCMEncrypt(key, nonce, plaintext, aad []byte) ([]byte, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("AES-CCM: key must be 16 bytes, got %d", len(key))
	}
	if len(nonce) != ccmNonceLen {
		return nil, fmt.Errorf("AES-CCM: nonce must be %d bytes, got %d", ccmNonceLen, len(nonce))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Compute CBC-MAC authentication tag.
	tag, err := ccmCBCMAC(block, nonce, plaintext, aad)
	if err != nil {
		return nil, err
	}

	// Encrypt plaintext and tag using CTR mode.
	out := make([]byte, len(plaintext)+ccmTagLen)
	ccmCTRKeystream(block, nonce, plaintext, tag, out)

	return out, nil
}

// CryptoCCMDecrypt decrypts ciphertextWithTag using AES-128-CCM and verifies the authentication tag.
// ciphertextWithTag is the concatenation of ciphertext || tag (tag is the last 16 bytes).
// Returns decrypted plaintext on success; returns ErrCCMAuthFailed if the tag is invalid.
// 4.7. Encryption.
func CryptoCCMDecrypt(key, nonce, ciphertextWithTag, aad []byte) ([]byte, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("AES-CCM: key must be 16 bytes, got %d", len(key))
	}
	if len(nonce) != ccmNonceLen {
		return nil, fmt.Errorf("AES-CCM: nonce must be %d bytes, got %d", ccmNonceLen, len(nonce))
	}
	if len(ciphertextWithTag) < ccmTagLen {
		return nil, fmt.Errorf("AES-CCM: input too short (%d bytes)", len(ciphertextWithTag))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := ciphertextWithTag[:len(ciphertextWithTag)-ccmTagLen]
	encTag := ciphertextWithTag[len(ciphertextWithTag)-ccmTagLen:]

	// Recover plaintext and authentication tag using CTR keystream.
	plaintext := make([]byte, len(ciphertext))
	tag := make([]byte, ccmTagLen)
	ccmCTRDecryptKeystream(block, nonce, ciphertext, encTag, plaintext, tag)

	// Recompute the expected tag over the decrypted plaintext.
	expectedTag, err := ccmCBCMAC(block, nonce, plaintext, aad)
	if err != nil {
		return nil, err
	}

	// Constant-time comparison to prevent timing attacks.
	if subtle.ConstantTimeCompare(tag, expectedTag) != 1 {
		return nil, ErrCCMAuthFailed
	}

	return plaintext, nil
}

// ccmCBCMAC computes the CBC-MAC over B_0 || formatted AAD || padded plaintext.
// Returns the first ccmTagLen bytes of the final CBC output.
func ccmCBCMAC(block cipher.Block, nonce, plaintext, aad []byte) ([]byte, error) {
	// Build B_0 block (NIST SP 800-38C, section 6.1).
	// Flags byte:
	//   bit 7   : reserved = 0
	//   bit 6   : Adata = 1 if len(aad) > 0
	//   bits 5-3: M' = (T-2)/2 = (16-2)/2 = 7
	//   bits 2-0: L' = L-1 = 1
	hasAAD := len(aad) > 0
	var adataBit byte
	if hasAAD {
		adataBit = 0x40
	}
	flags := adataBit | byte(((ccmTagLen-2)/2)<<3) | byte(ccmL-1)

	b0 := make([]byte, ccmBlockSize)
	b0[0] = flags
	copy(b0[1:1+ccmNonceLen], nonce)
	// Encode message length Q in ccmL=2 big-endian bytes.
	binary.BigEndian.PutUint16(b0[1+ccmNonceLen:], uint16(len(plaintext))) //nolint:gosec

	// Initialize CBC-MAC with B_0.
	mac := make([]byte, ccmBlockSize)
	block.Encrypt(mac, b0)

	// Process AAD if present.
	if hasAAD {
		// For 0 < len(aad) < 0xFF00, encode length as 2-byte big-endian prefix.
		aadLen := len(aad)
		header := []byte{byte(aadLen >> 8), byte(aadLen & 0xFF)}
		aadBlock := append(header, aad...) //nolint:gocritic
		// Pad to block boundary.
		if rem := len(aadBlock) % ccmBlockSize; rem != 0 {
			aadBlock = append(aadBlock, make([]byte, ccmBlockSize-rem)...)
		}
		for i := 0; i < len(aadBlock); i += ccmBlockSize {
			xorBlock(mac, mac, aadBlock[i:i+ccmBlockSize])
			block.Encrypt(mac, mac)
		}
	}

	// Process plaintext blocks.
	if len(plaintext) > 0 {
		ptPadded := make([]byte, len(plaintext))
		copy(ptPadded, plaintext)
		if rem := len(ptPadded) % ccmBlockSize; rem != 0 {
			ptPadded = append(ptPadded, make([]byte, ccmBlockSize-rem)...)
		}
		for i := 0; i < len(ptPadded); i += ccmBlockSize {
			xorBlock(mac, mac, ptPadded[i:i+ccmBlockSize])
			block.Encrypt(mac, mac)
		}
	}

	return mac[:ccmTagLen], nil
}

// ccmCTRKeystream encrypts plaintext with CTR mode and produces the output ciphertext || encrypted-tag.
// Counter block A_i format:
//
//	byte 0   : flags = L-1 = 1
//	bytes 1-13: nonce
//	bytes 14-15: counter i, big-endian (2 bytes for L=2)
func ccmCTRKeystream(block cipher.Block, nonce, plaintext, tag, out []byte) {
	ctr := ccmCounterBlock(nonce, 0)
	s0 := make([]byte, ccmBlockSize)
	block.Encrypt(s0, ctr)
	// Encrypt tag: out[len(plaintext):] = tag XOR s0[:ccmTagLen]
	for i := 0; i < ccmTagLen; i++ {
		out[len(plaintext)+i] = tag[i] ^ s0[i]
	}
	// Encrypt plaintext blocks with counters A_1, A_2, ...
	for i := 0; i < len(plaintext); i += ccmBlockSize {
		counterVal := uint16(i/ccmBlockSize + 1) //nolint:gosec
		ctr = ccmCounterBlock(nonce, counterVal)
		si := make([]byte, ccmBlockSize)
		block.Encrypt(si, ctr)
		end := i + ccmBlockSize
		if end > len(plaintext) {
			end = len(plaintext)
		}
		for j := i; j < end; j++ {
			out[j] = plaintext[j] ^ si[j-i]
		}
	}
}

// ccmCTRDecryptKeystream decrypts ciphertext and recovers the authentication tag from encTag.
func ccmCTRDecryptKeystream(block cipher.Block, nonce, ciphertext, encTag, plaintext, tag []byte) {
	// Recover the authentication tag using A_0.
	ctr := ccmCounterBlock(nonce, 0)
	s0 := make([]byte, ccmBlockSize)
	block.Encrypt(s0, ctr)
	for i := 0; i < ccmTagLen; i++ {
		tag[i] = encTag[i] ^ s0[i]
	}
	// Decrypt ciphertext blocks.
	for i := 0; i < len(ciphertext); i += ccmBlockSize {
		counterVal := uint16(i/ccmBlockSize + 1) //nolint:gosec
		ctr = ccmCounterBlock(nonce, counterVal)
		si := make([]byte, ccmBlockSize)
		block.Encrypt(si, ctr)
		end := i + ccmBlockSize
		if end > len(ciphertext) {
			end = len(ciphertext)
		}
		for j := i; j < end; j++ {
			plaintext[j] = ciphertext[j] ^ si[j-i]
		}
	}
}

// ccmCounterBlock builds the CCM counter block A_i.
func ccmCounterBlock(nonce []byte, counter uint16) []byte {
	ctr := make([]byte, ccmBlockSize)
	ctr[0] = byte(ccmL - 1) // flags = L-1 = 1
	copy(ctr[1:1+ccmNonceLen], nonce)
	binary.BigEndian.PutUint16(ctr[1+ccmNonceLen:], counter)
	return ctr
}

// xorBlock computes dst[i] = a[i] XOR b[i] for each byte.
func xorBlock(dst, a, b []byte) {
	for i := range dst {
		dst[i] = a[i] ^ b[i]
	}
}

// CryptoCCMNonce builds the 13-byte CCM nonce from Matter message header fields.
// Nonce layout (spec section 4.7.2):
//
//	byte 0   : SecurityFlags (1 byte)
//	bytes 1-4: MessageCounter (4 bytes, little-endian)
//	bytes 5-12: SourceNodeID (8 bytes, little-endian; 0 if absent)
//
// 4.7.2. Cryptographic nonce.
func CryptoCCMNonce(securityFlags byte, messageCounter uint32, sourceNodeID uint64) []byte {
	nonce := make([]byte, ccmNonceLen)
	nonce[0] = securityFlags
	binary.LittleEndian.PutUint32(nonce[1:5], messageCounter)
	binary.LittleEndian.PutUint64(nonce[5:13], sourceNodeID)
	return nonce
}
