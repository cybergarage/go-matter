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
	"fmt"
	"strconv"
	"sync"
)

// PersistentCounter is a uint32 counter that never repeats a value across
// restarts without writing on every increment. It persists an upper bound
// reserve values ahead of the current value, hands values out from memory
// until it reaches that bound, and then persists the next bound. After a
// restart it resumes at the persisted bound, skipping at most reserve
// values that were reserved but never used.
//
// This is the scheme Matter expects for counters that must not repeat,
// such as the global group message counters (Matter Core 4.6.1.2). A
// reserve of 1 persists on every increment, which suits a counter that
// changes rarely, such as the boot count.
//
// The counter wraps from 0xFFFFFFFF to 0. Whether that is allowed is up
// to the caller.
type PersistentCounter struct {
	mu      sync.Mutex
	kv      KVStore
	key     string
	reserve uint32
	next    uint32
	limit   uint32
}

// NewPersistentCounter opens the counter stored under key. initial is the
// first value of a counter that has never been persisted. reserve must be
// at least 1.
func NewPersistentCounter(kv KVStore, key string, reserve, initial uint32) (*PersistentCounter, error) {
	if reserve == 0 {
		return nil, fmt.Errorf("store: counter %s: reserve must be at least 1", key)
	}
	if err := ValidateKey(key); err != nil {
		return nil, err
	}
	start := initial
	b, err := kv.Get(key)
	switch {
	case err == nil:
		v, perr := strconv.ParseUint(string(b), 10, 32)
		if perr != nil {
			return nil, fmt.Errorf("store: counter %s: parse %q: %w", key, b, perr)
		}
		start = uint32(v)
	case errors.Is(err, ErrNotFound):
	default:
		return nil, err
	}
	// limit == next means nothing is reserved yet, so the first Next
	// persists a bound before it hands out a value.
	return &PersistentCounter{
		mu:      sync.Mutex{},
		kv:      kv,
		key:     key,
		reserve: reserve,
		next:    start,
		limit:   start,
	}, nil
}

// Next returns the counter's current value and advances it. It returns an
// error, without advancing, when the next bound cannot be persisted.
func (c *PersistentCounter) Next() (uint32, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.next == c.limit {
		limit := c.next + c.reserve
		if err := c.kv.Set(c.key, []byte(strconv.FormatUint(uint64(limit), 10))); err != nil {
			return 0, fmt.Errorf("store: counter %s: persist: %w", c.key, err)
		}
		c.limit = limit
	}
	v := c.next
	c.next++
	return v, nil
}

// Peek returns the value the next call to Next will return.
func (c *PersistentCounter) Peek() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.next
}
