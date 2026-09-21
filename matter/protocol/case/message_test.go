// Copyright (C) 2025 The go-matter Authors. All rights reserved.
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

package caseprotocol

import (
	"encoding/hex"
	"testing"
)

// TestDecodeSigma2WithResponderSessionParams is a regression test built from
// a real device's Sigma2 response (captured over the wire). It includes the
// optional ResponderSessionParams structure at tag 5, containing its own
// tags 1-4 — decodeSigma2's flat TLV walk used to keep processing those
// nested tags as if they were top-level Sigma2 fields, clobbering the
// already-decoded ResponderRandom (tag 1) with the empty bytes read back
// from the nested SessionIdleInterval (also tag 1, but an integer, so
// Element.Bytes() on it fails and zeroes the field). That corruption never
// showed up against synthetic/mock Sigma2 payloads that omit this optional
// structure, only against a real commissionee that sends it.
func TestDecodeSigma2WithResponderSessionParams(t *testing.T) {
	const raw = "15300120F6F0E7A4F8E98758F90CB615730CA10E5AC677DC7EEB844D9134FF69A32DF1E42502215030034104EF36B9A0B7B7A5A208BC3D698F9D77410990ADE8F36CA409EBE0BC531F546277976C9DF580701DA505A274C441035F1DB8C03FF2B372D7F74EA4977E1B7026E731049701C2CDD01F321D358385B7CF9E21DAA28FDB14ECE3FE186D5A2939D2623B25E446D7411EB63D0C4658A8B2901F4EE488585D23A8844819A36DAC12D190047BD7530FAD60FE079FCCCD8FC160C6BACB9AADAC6C217B15C14952683BAB0C09864EC91AB1FD5F144BC7147F5B3D00F74DF4125AA898F0EC8CBE558CFC4902D84449B15AB80CA42B7710DFA3EF54B928F9CB0877EF486D66EFC7B5193FA13CE394FA16DC0A543DCD007E52B0B13F457D79364A47DD2858E3CF4C56802C057964C064992F7DFAC46322F911DA44E2615BDB17EE2553CC8CD2B3E8D991192BDCDC7B4DDD26813039361A5F35C8A012AC2CD12C0F004540F744EF7EC92D54B857543064A5796AA2947F832A93658ECA8FF1A76D717E1CE1387226C3ECA3D8ABE54078F487384069E2A34281A6F08EC28122EADF2D7954B4A97650A796AE98943C6B4E090AAC839533116B9AB008A3CE4791E8D14A83531886443B3AA911AE656D860AAC5C67B979DB21AAFAB128749A8977198AF72A30BEA7AF14A2E2CD50EC4F6E45B23198FEF4F4A4BA07A6568C3DD1CEE8E05B0D330B34FF92E335012503A00F240411012407011818"

	b, err := hex.DecodeString(raw)
	if err != nil {
		t.Fatalf("hex.DecodeString() error = %v", err)
	}

	got, err := decodeSigma2(b)
	if err != nil {
		t.Fatalf("decodeSigma2() error = %v", err)
	}
	if len(got.ResponderRandom) != randomLen {
		t.Errorf("ResponderRandom length = %d, want %d", len(got.ResponderRandom), randomLen)
	}
	if got.ResponderSessionID != 20513 {
		t.Errorf("ResponderSessionID = %d, want 20513", got.ResponderSessionID)
	}
	if len(got.ResponderEphPubKey) != 65 {
		t.Errorf("ResponderEphPubKey length = %d, want 65", len(got.ResponderEphPubKey))
	}
	if len(got.Encrypted2) != 407 {
		t.Errorf("Encrypted2 length = %d, want 407", len(got.Encrypted2))
	}
}
