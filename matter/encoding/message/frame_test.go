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

package message

import "testing"

func TestFrameEncodeDecodeRoundtrip(t *testing.T) {
	frame := NewFrame(
		NewHeader(
			WithHeaderFlags(0x00),
			WithHeaderSessionID(0x0000),
			WithHeaderSecurityFlags(0x00),
			WithHeaderMessageCounter(1),
		),
		[]byte{0x01, 0x02, 0x03, 0x04},
	)

	encoded := frame.Bytes()
	decoded, err := DecodeFrame(encoded)
	if err != nil {
		t.Fatalf("DecodeFrame failed: %v", err)
	}

	if decoded.Header().MessageCounter() != frame.Header().MessageCounter() {
		t.Errorf("MessageCounter mismatch: got %d, want %d", decoded.Header().MessageCounter(), frame.Header().MessageCounter())
	}
	if len(decoded.Payload()) != len(frame.Payload()) {
		t.Errorf("Payload length mismatch: got %d, want %d", len(decoded.Payload()), len(frame.Payload()))
	}
}
