// Copyright (C) 2026 The go-matter Authors. Licensed under the Apache License, Version 2.0.

package matter

import (
	"context"
	"testing"

	"github.com/cybergarage/go-matter/matter/config"
	"github.com/cybergarage/go-matter/matter/store"
	"github.com/cybergarage/go-matter/matter/types"
)

func TestCommissionNodeAllocationRejectsDuplicateBeforeDiscovery(t *testing.T) {
	st := store.NewMemStore()
	_ = st.SaveCommissionee(store.CommissioneeRecord{NodeID: 42})
	c := &commissioner{store: st, adminConfig: config.NewAdministratorConfig(config.WithAdministratorNodeID(1))}
	for _, id := range []CommissionNodeID{1, 42, 0xFFFFFFFFFFFFFFFF} {
		// No central/discoverer installed: reaching discovery would panic.
		if _, err := c.Commission(context.Background(), nil, id); err == nil {
			t.Fatal("reserved node accepted")
		}
	}
	opts, err := c.allocateCommissionNode(c.commissionOptions(CommissionNodeID(0)))
	if err != nil {
		t.Fatal(err)
	}
	n, err := commissionNodeID(opts)
	if err != nil || !types.NodeID(n).IsOperational() || n == 1 || n == 42 {
		t.Fatal("invalid automatic ID")
	}
	opts, err = c.allocateCommissionNode(c.commissionOptions(CommissionNodeID(123)))
	if err != nil {
		t.Fatal(err)
	}
	n, _ = commissionNodeID(opts)
	if n != 123 {
		t.Fatal("explicit ID changed")
	}
	dev := newBaseDevice()
	if dev.parseCommissionOptions(opts...) != nil || dev.nodeID != 123 {
		t.Fatal("device ignored node option")
	}
}
