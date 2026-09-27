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

// Package store persists a Commissioner's fabric identity and per-device
// commissioning records, so a controller built on this library can resume
// the same fabric and recall which devices it has already commissioned
// across process restarts.
//
// The package has two layers. KVStore (and TxKVStore, for atomic
// multi-key updates) is the backend: FileKVStore keeps one file per key
// under a directory, MemKVStore keeps everything in memory, and any other
// backend can be plugged in by implementing the interface. Store is the
// typed layer on top, built with NewStoreWithKVStore; NewStore and
// NewMemStore are shorthands for the two built-in backends.
package store

// Store persists a Commissioner's fabric-wide identity (FabricRecord) and
// its per-commissioned-device records (CommissioneeRecord) to a KVStore.
type Store interface {
	// SaveFabric writes rec as the fabric-wide identity, replacing any
	// previously saved record.
	SaveFabric(rec FabricRecord) error
	// LoadFabric reads the fabric-wide identity. ok is false, with a nil
	// error, when no fabric identity has been saved yet.
	LoadFabric() (rec FabricRecord, ok bool, err error)
	// SaveCommissionee writes rec, keyed by its CompressedFabricID and
	// NodeID, replacing any previously saved record for the same device.
	SaveCommissionee(rec CommissioneeRecord) error
	// LoadCommissionee reads the record for the device identified by
	// compressedFabricID/nodeID. ok is false, with a nil error, when no
	// such record has been saved.
	LoadCommissionee(compressedFabricID, nodeID uint64) (rec CommissioneeRecord, ok bool, err error)
	// DeleteCommissionee removes the record for the device identified by
	// compressedFabricID/nodeID. Deleting a record that does not exist is
	// not an error.
	DeleteCommissionee(compressedFabricID, nodeID uint64) error
	// ListCommissionees returns every saved commissionee record, in no
	// particular order.
	ListCommissionees() ([]CommissioneeRecord, error)
}
