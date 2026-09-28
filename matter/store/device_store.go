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

// DeviceStoreReader reads a device's per-fabric state.
type DeviceStoreReader interface {
	// LoadDeviceFabric reads the fabric at fabricIndex. ok is false, with a
	// nil error, when the device has no such fabric.
	LoadDeviceFabric(fabricIndex uint8) (rec DeviceFabricRecord, ok bool, err error)
	// LoadACL reads the Access Control entries of the fabric at
	// fabricIndex, in order. It returns no entries when none are stored.
	LoadACL(fabricIndex uint8) ([]ACLEntry, error)
	// LoadGroupKeys reads the group key sets and key map of the fabric at
	// fabricIndex. It returns an empty record when none is stored.
	LoadGroupKeys(fabricIndex uint8) (GroupKeysRecord, error)
}

// DeviceStoreWriter writes a device's per-fabric state.
type DeviceStoreWriter interface {
	// SaveDeviceFabric writes rec under rec.FabricIndex, replacing any
	// previous record for that index.
	SaveDeviceFabric(rec DeviceFabricRecord) error
	// SaveACL replaces the Access Control entries of the fabric at
	// fabricIndex. An empty entries removes them.
	SaveACL(fabricIndex uint8, entries []ACLEntry) error
	// SaveGroupKeys replaces the group key state of the fabric at
	// fabricIndex.
	SaveGroupKeys(fabricIndex uint8, rec GroupKeysRecord) error
	// RemoveDeviceFabric removes the fabric at fabricIndex together with
	// its ACL and group keys, as RemoveFabric does (Matter Core 11.18.6.12).
	// Removing a fabric that does not exist is not an error.
	RemoveDeviceFabric(fabricIndex uint8) error
}

// DeviceStoreTx groups writes to a DeviceStore into one atomic update. A
// device opens one when a fail-safe is armed, writes what AddNOC,
// UpdateNOC, the ACL and the group key writes change through it, and
// commits it on CommissioningComplete or rolls it back when the fail-safe
// expires. Reads see the transaction's own pending writes.
type DeviceStoreTx interface {
	DeviceStoreReader
	DeviceStoreWriter
	Commit() error
	Rollback() error
}

// DeviceStore persists what a Matter device must keep across restarts:
// the fabrics it has joined with their operational credentials, the
// Access Control entries and the group keys of each fabric, and
// persistent counters such as the boot count and the group message
// counters.
type DeviceStore interface {
	DeviceStoreReader
	DeviceStoreWriter
	// ListDeviceFabrics returns every stored fabric, ordered by fabric
	// index.
	ListDeviceFabrics() ([]DeviceFabricRecord, error)
	// Begin starts a transaction.
	Begin() (DeviceStoreTx, error)
	// Counter opens the persistent counter called name; see
	// PersistentCounter. initial is its first value when it has never been
	// used.
	Counter(name string, reserve, initial uint32) (*PersistentCounter, error)
}
