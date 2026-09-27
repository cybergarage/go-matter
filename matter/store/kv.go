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
	"strings"
)

// ErrNotFound is returned by KVStore.Get and Tx.Get when no value is
// stored under the requested key.
var ErrNotFound = errors.New("store: key not found")

// ErrTxDone is returned by a Tx method called after Commit or Rollback.
var ErrTxDone = errors.New("store: transaction already committed or rolled back")

// KVStore is the backend a typed store (Store, and the stores a device
// implementation will need) is built on: a flat namespace of byte values
// addressed by slash-separated keys such as "fabric.json" or
// "commissions/0000000000001111-0000000000002222.json".
//
// A key is one or more non-empty segments separated by "/". A segment may
// only contain ASCII letters, digits, '.', '-' and '_', must not start with
// '.', and so can never be "." or "..". Leading-dot names are reserved for
// the backends' own bookkeeping (temporary files, journals).
//
// Implementations must be safe for concurrent use.
type KVStore interface {
	// Get returns the value stored under key, or an error wrapping
	// ErrNotFound when there is none.
	Get(key string) ([]byte, error)
	// Set stores value under key, replacing any previous value. A single
	// Set is atomic: a reader sees either the old or the new value, never
	// a partial one, even across a crash.
	Set(key string, value []byte) error
	// Delete removes key. Deleting a key that does not exist is not an
	// error.
	Delete(key string) error
	// List returns every key that starts with prefix, sorted. An empty
	// prefix lists every key.
	List(prefix string) ([]string, error)
}

// TxKVStore is a KVStore that can group several writes into one atomic
// update. A device needs this for the fail-safe timer: the NOC, the ACL
// and the fabric table written during commissioning must all be committed
// together, or all be rolled back when the fail-safe expires.
type TxKVStore interface {
	KVStore
	// Begin starts a transaction. Writes made through the Tx are invisible
	// to the store until Commit.
	Begin() (Tx, error)
}

// Tx is a set of pending writes against a TxKVStore. Get reads the
// transaction's own pending writes first, then the store. Only one of
// Commit or Rollback may be called; any call after that returns ErrTxDone.
type Tx interface {
	Get(key string) ([]byte, error)
	Set(key string, value []byte) error
	Delete(key string) error
	// Commit applies every pending write atomically: after a crash the
	// store holds either all of them or none of them.
	Commit() error
	// Rollback discards every pending write.
	Rollback() error
}

// ValidateKey reports whether key is a well-formed KVStore key.
func ValidateKey(key string) error {
	if key == "" {
		return fmt.Errorf("store: empty key")
	}
	for seg := range strings.SplitSeq(key, "/") {
		if seg == "" {
			return fmt.Errorf("store: key %q has an empty segment", key)
		}
		if seg[0] == '.' {
			return fmt.Errorf("store: key %q has a segment starting with '.'", key)
		}
		for _, c := range seg {
			if !isKeyChar(c) {
				return fmt.Errorf("store: key %q contains %q", key, c)
			}
		}
	}
	return nil
}

func isKeyChar(c rune) bool {
	switch {
	case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		return true
	case c == '.', c == '-', c == '_':
		return true
	default:
		return false
	}
}

func notFound(key string) error {
	return fmt.Errorf("%w: %s", ErrNotFound, key)
}

// txOp is one pending write inside a transaction; a nil value with
// deleted set means Delete.
type txOp struct {
	Key     string `json:"key"`
	Value   []byte `json:"value,omitempty"`
	Deleted bool   `json:"deleted,omitempty"`
}

// txBuffer holds a transaction's pending writes in the order they were
// made, with the latest write per key winning.
type txBuffer struct {
	ops   []txOp
	index map[string]int
	done  bool
}

func newTxBuffer() *txBuffer {
	return &txBuffer{ops: nil, index: map[string]int{}, done: false}
}

func (b *txBuffer) put(op txOp) error {
	if b.done {
		return ErrTxDone
	}
	if err := ValidateKey(op.Key); err != nil {
		return err
	}
	if op.Value != nil {
		op.Value = append([]byte(nil), op.Value...)
	}
	if i, ok := b.index[op.Key]; ok {
		b.ops[i] = op
		return nil
	}
	b.index[op.Key] = len(b.ops)
	b.ops = append(b.ops, op)
	return nil
}

// lookup returns the pending write for key, if any.
func (b *txBuffer) lookup(key string) (txOp, bool) {
	i, ok := b.index[key]
	if !ok {
		return txOp{}, false
	}
	return b.ops[i], true
}

func (b *txBuffer) get(key string, fallback func(string) ([]byte, error)) ([]byte, error) {
	if b.done {
		return nil, ErrTxDone
	}
	if op, ok := b.lookup(key); ok {
		if op.Deleted {
			return nil, notFound(key)
		}
		return append([]byte(nil), op.Value...), nil
	}
	return fallback(key)
}
