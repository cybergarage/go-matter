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

package btp

import (
	"bytes"
	"testing"
)

func TestSegmenterEncodeMessageSingleFragment(t *testing.T) {
	s := NewSegmenter(64)
	payload := []byte("hello matter")

	segs := s.EncodeMessage(payload)
	if len(segs) != 1 {
		t.Fatalf("EncodeMessage() produced %d segments, want 1", len(segs))
	}

	seg := segs[0]
	want := []byte{headerFlagStartMessage | headerFlagEndMessage, 0x00, byte(len(payload)), 0x00}
	want = append(want, payload...)
	if !bytes.Equal(seg, want) {
		t.Errorf("segment = % X, want % X", seg, want)
	}
}

func TestSegmenterEncodeMessageMultiFragment(t *testing.T) {
	// Fragment size of 6 leaves 2 bytes of payload per first fragment
	// (4-byte header: flags+seq+2 length bytes) and 4 bytes per following
	// fragment (2-byte header: flags+seq).
	s := NewSegmenter(6)
	payload := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9}

	segs := s.EncodeMessage(payload)
	if len(segs) != 3 {
		t.Fatalf("EncodeMessage() produced %d segments, want 3: %v", len(segs), segs)
	}

	wantFirst := []byte{headerFlagStartMessage, 0x00, byte(len(payload)), 0x00, 1, 2}
	if !bytes.Equal(segs[0], wantFirst) {
		t.Errorf("segment[0] = % X, want % X", segs[0], wantFirst)
	}
	wantSecond := []byte{headerFlagContinueMessage, 0x01, 3, 4, 5, 6}
	if !bytes.Equal(segs[1], wantSecond) {
		t.Errorf("segment[1] = % X, want % X", segs[1], wantSecond)
	}
	wantThird := []byte{headerFlagContinueMessage | headerFlagEndMessage, 0x02, 7, 8, 9}
	if !bytes.Equal(segs[2], wantThird) {
		t.Errorf("segment[2] = % X, want % X", segs[2], wantThird)
	}
}

func TestSegmenterFeedSingleFragment(t *testing.T) {
	s := NewSegmenter(64)
	payload := []byte("pong")
	// As received from a peripheral, whose own tx sequence starts at 1.
	seg := append([]byte{headerFlagStartMessage | headerFlagEndMessage, 0x01, byte(len(payload)), 0x00}, payload...)

	msg, ok, err := s.Feed(seg)
	if err != nil {
		t.Fatalf("Feed() error = %v", err)
	}
	if !ok {
		t.Fatal("Feed() ok = false, want true")
	}
	if !bytes.Equal(msg, payload) {
		t.Errorf("Feed() message = % X, want % X", msg, payload)
	}
}

func TestSegmenterFeedMultiFragment(t *testing.T) {
	s := NewSegmenter(64)
	payload := []byte("this message spans two segments")

	first := append([]byte{headerFlagStartMessage, 0x01, byte(len(payload)), 0x00}, payload[:10]...)
	second := append([]byte{headerFlagContinueMessage | headerFlagEndMessage, 0x02}, payload[10:]...)

	_, ok, err := s.Feed(first)
	if err != nil {
		t.Fatalf("Feed(first) error = %v", err)
	}
	if ok {
		t.Fatal("Feed(first) ok = true, want false (message incomplete)")
	}

	msg, ok, err := s.Feed(second)
	if err != nil {
		t.Fatalf("Feed(second) error = %v", err)
	}
	if !ok {
		t.Fatal("Feed(second) ok = false, want true")
	}
	if !bytes.Equal(msg, payload) {
		t.Errorf("Feed() message = % X, want % X", msg, payload)
	}
}

func TestSegmenterFeedRejectsUnexpectedSequenceNumber(t *testing.T) {
	s := NewSegmenter(64)
	// Peripheral's first segment must have sequence number 1, not 0.
	seg := []byte{headerFlagStartMessage | headerFlagEndMessage, 0x00, 0x00, 0x00}

	if _, _, err := s.Feed(seg); err == nil {
		t.Fatal("Feed() error = nil, want non-nil for out-of-order sequence number")
	}
}

func TestSegmenterEncodeMessagePiggybacksAck(t *testing.T) {
	s := NewSegmenter(64)
	payload := []byte("x")
	seg := append([]byte{headerFlagStartMessage | headerFlagEndMessage, 0x01, byte(len(payload)), 0x00}, payload...)
	if _, _, err := s.Feed(seg); err != nil {
		t.Fatalf("Feed() error = %v", err)
	}

	outPayload := []byte("y")
	segs := s.EncodeMessage(outPayload)
	if len(segs) != 1 {
		t.Fatalf("EncodeMessage() produced %d segments, want 1", len(segs))
	}
	got := segs[0]
	want := []byte{headerFlagStartMessage | headerFlagEndMessage | headerFlagFragmentAck, 0x01, 0x00, byte(len(outPayload)), 0x00}
	want = append(want, outPayload...)
	if !bytes.Equal(got, want) {
		t.Errorf("segment = % X, want % X", got, want)
	}
}
