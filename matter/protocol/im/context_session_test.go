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

package im

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cybergarage/go-matter/matter/protocol/session"
)

func TestWithContextEndsTheWaitForAResponse(t *testing.T) {
	// A peer which never answers.
	out := make(chan []byte, 64)
	closed := make(chan struct{})
	t.Cleanup(func() { close(closed) })
	sess := session.NewSecureSession(&chanTransport{in: make(chan []byte), out: out, closed: closed}, serverTestKeys{})
	mux := NewExchangeMux(sess, WithResponseTimeout(time.Minute))
	t.Cleanup(func() { _ = mux.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := ReadAttribute(WithContext(ctx, mux), 1, 6, 0)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ReadAttribute() error = %v, want the context's", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("ReadAttribute() returned after %v, not when its context ended", elapsed)
	}
}

func TestWithContextDoesNotSendOnceDone(t *testing.T) {
	out := make(chan []byte, 64)
	closed := make(chan struct{})
	t.Cleanup(func() { close(closed) })
	sess := session.NewSecureSession(&chanTransport{in: make(chan []byte), out: out, closed: closed}, serverTestKeys{})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Invoke(WithContext(ctx, sess), 1, 6, 1, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("Invoke() error = %v, want context.Canceled", err)
	}
	if len(out) != 0 {
		t.Fatalf("%d messages sent after the context was done", len(out))
	}
}

func TestWithContextAnswersWhileLive(t *testing.T) {
	var on atomic.Bool
	on.Store(true)
	client, _ := startServerWithClose(t, onOffServer(&on))
	mux := newTestMux(t, client)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := ReadBoolAttribute(WithContext(ctx, mux), onOffPath.Endpoint, onOffPath.Cluster, onOffPath.Attribute)
	if err != nil || !resp {
		t.Fatalf("ReadBoolAttribute() = %v, %v; want true, nil", resp, err)
	}
}
