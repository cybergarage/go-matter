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

package message

import (
	"bytes"
	"testing"
)

// TestBasicFrameCodec verifies encode/decode round-trip for a basic frame using WithFrameOption.
func TestBasicFrameCodec(t *testing.T) {
	codec := NewBasicFrameCodec()

	fr := NewBasicFrameWith(
		WithVersion(FrameVersion1),
		WithType(FrameTypeSecure),
		WithSourceNodeIDPresent(true),
		WithDestNodeIDPresent(false),
		WithSessionID(0x1234),
		WithSecurityFlags(0x01),
		WithMessageCounter(0x01020304),
		WithSourceNodeID(0xAABBCCDDEEFF0011),
		WithPayload([]byte("hello-matter")),
	)

	enc, err := codec.Encode(fr)
	if err != nil {
		t.Fatalf("encode error: %v", err)
	}

	if err := codec.Validate(enc); err != nil {
		t.Fatalf("validate error: %v", err)
	}

	dec, err := codec.Decode(enc)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}

	if dec.Version() != fr.Version() ||
		dec.Type() != fr.Type() ||
		dec.SessionID() != fr.SessionID() ||
		dec.MessageCounter() != fr.MessageCounter() ||
		!bytes.Equal(dec.Payload(), fr.Payload()) {
		t.Fatalf("decoded frame mismatch: %+v vs %+v", dec, fr)
	}
}
