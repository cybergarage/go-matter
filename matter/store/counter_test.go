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

package store

import (
	"errors"
	"sync"
	"testing"
)

func TestPersistentCounterNeverRepeatsAcrossRestarts(t *testing.T) {
	kv := NewMemKVStore()
	const key = "counters/msg"

	c, err := NewPersistentCounter(kv, key, 10, 100)
	if err != nil {
		t.Fatal(err)
	}
	for want := uint32(100); want < 103; want++ {
		if got, err := c.Next(); err != nil || got != want {
			t.Fatalf("Next() = (%d, %v), want (%d, nil)", got, err, want)
		}
	}
	if got, _ := kv.Get(key); string(got) != "110" {
		t.Fatalf("persisted bound = %q, want 110", got)
	}

	// A restart resumes at the persisted bound: 103..109 are skipped, and
	// none of 100..102 is handed out again.
	c, err = NewPersistentCounter(kv, key, 10, 100)
	if err != nil {
		t.Fatal(err)
	}
	if c.Peek() != 110 {
		t.Fatalf("Peek() after restart = %d, want 110", c.Peek())
	}
	if got, _ := c.Next(); got != 110 {
		t.Fatalf("Next() after restart = %d, want 110", got)
	}
	if got, _ := kv.Get(key); string(got) != "120" {
		t.Fatalf("persisted bound after restart = %q, want 120", got)
	}
}

func TestPersistentCounterReserveOne(t *testing.T) {
	kv := NewMemKVStore()
	for boot := uint32(0); boot < 3; boot++ {
		c, err := NewPersistentCounter(kv, "boot", 1, 0)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := c.Next(); err != nil || got != boot {
			t.Fatalf("boot %d: Next() = (%d, %v), want (%d, nil)", boot, got, err, boot)
		}
	}
}

func TestPersistentCounterWraps(t *testing.T) {
	c, err := NewPersistentCounter(NewMemKVStore(), "c", 2, 0xFFFFFFFE)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []uint32{0xFFFFFFFE, 0xFFFFFFFF, 0, 1, 2} {
		if got, err := c.Next(); err != nil || got != want {
			t.Fatalf("Next() = (%#x, %v), want (%#x, nil)", got, err, want)
		}
	}
}

func TestPersistentCounterConcurrent(t *testing.T) {
	c, err := NewPersistentCounter(NewMemKVStore(), "c", 7, 0)
	if err != nil {
		t.Fatal(err)
	}
	const workers, per = 8, 100
	seen := make(chan uint32, workers*per)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range per {
				v, err := c.Next()
				if err != nil {
					t.Error(err)
					return
				}
				seen <- v
			}
		}()
	}
	wg.Wait()
	close(seen)
	got := map[uint32]bool{}
	for v := range seen {
		if got[v] {
			t.Fatalf("value %d handed out twice", v)
		}
		got[v] = true
	}
	if len(got) != workers*per {
		t.Fatalf("got %d distinct values, want %d", len(got), workers*per)
	}
}

func TestPersistentCounterRejectsBadInput(t *testing.T) {
	kv := NewMemKVStore()
	if _, err := NewPersistentCounter(kv, "c", 0, 0); err == nil {
		t.Error("reserve 0: error = nil, want an error")
	}
	if _, err := NewPersistentCounter(kv, "../c", 1, 0); err == nil {
		t.Error("invalid key: error = nil, want an error")
	}
	if err := kv.Set("c", []byte("not a number")); err != nil {
		t.Fatal(err)
	}
	if _, err := NewPersistentCounter(kv, "c", 1, 0); err == nil {
		t.Error("corrupt value: error = nil, want an error")
	}
}

// failingKV fails every Set, to check that Next does not hand out a value
// it could not reserve.
type failingKV struct{ KVStore }

var errSetFailed = errors.New("set failed")

func (failingKV) Set(string, []byte) error { return errSetFailed }

func TestPersistentCounterDoesNotAdvanceOnPersistFailure(t *testing.T) {
	c, err := NewPersistentCounter(failingKV{NewMemKVStore()}, "c", 5, 42)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Next(); !errors.Is(err, errSetFailed) {
		t.Fatalf("Next() error = %v, want errSetFailed", err)
	}
	if c.Peek() != 42 {
		t.Fatalf("Peek() after a failed Next = %d, want 42", c.Peek())
	}
}
