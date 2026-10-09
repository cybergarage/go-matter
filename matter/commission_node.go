// Copyright (C) 2026 The go-matter Authors. Licensed under the Apache License, Version 2.0.

package matter

import (
	"errors"

	"github.com/cybergarage/go-matter/matter/credentials"
	"github.com/cybergarage/go-matter/matter/types"
)

// CommissionNodeID requests a specific operational Node ID. Zero means automatic.
// Pass as a CommissionOption. Existing numeric CLI node arguments now honor this option.
type CommissionNodeID uint64

func commissionNodeID(opts []CommissionOption) (uint64, error) {
	var n uint64
	for _, opt := range opts {
		if id, ok := opt.(CommissionNodeID); ok {
			n = uint64(id)
		}
	}
	if n != 0 && !types.NodeID(n).IsOperational() {
		return 0, errors.New("invalid operational node ID")
	}
	return n, nil
}

func (cmr *commissioner) allocateCommissionNode(opts []CommissionOption) ([]CommissionOption, error) {
	n, err := commissionNodeID(opts)
	if err != nil {
		return nil, err
	}
	requested := n != 0
	used := map[uint64]bool{}
	// Reserve administrator and saved IDs before discovery or commissioning.
	admin, _ := effectiveConfigOptions(opts)
	if admin != nil {
		id, _ := admin.NodeID()
		used[id] = true
	}
	if cmr.store != nil {
		records, err := cmr.store.ListCommissionees()
		if err != nil {
			return nil, errors.New("cannot check saved node IDs")
		}
		for _, r := range records {
			used[r.NodeID] = true
		}
	}
	for range 32 {
		if n == 0 {
			n, err = credentials.RandomOperationalID()
			if err != nil {
				return nil, err
			}
		}
		if !used[n] {
			return append(opts, CommissionNodeID(n)), nil
		}
		if requested {
			return nil, errors.New("node ID is already reserved or commissioned")
		}
		n = 0
	}
	return nil, errors.New("cannot allocate an unused node ID")
}
