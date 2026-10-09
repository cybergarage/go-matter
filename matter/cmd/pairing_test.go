// Copyright (C) 2026 The go-matter Authors. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package cmd

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cybergarage/go-matter/matter"
	"github.com/spf13/cobra"
)

type deadlineCommissioner struct {
	matter.Commissioner
	deadline time.Time
}

func (c *deadlineCommissioner) Commission(ctx context.Context, _ matter.OnboardingPayload, _ ...matter.CommissionOption) (matter.Commissionee, error) {
	c.deadline, _ = ctx.Deadline()
	return nil, errors.New("synthetic commissioning failure")
}
func TestPairingCLIBudgetCoversEntireExchange(t *testing.T) {
	prev := sharedCommissioner
	t.Cleanup(func() { sharedCommissioner = prev })
	for _, cmd := range []*cobra.Command{pairingCodeCmd, pairingCodeWifiCmd} {
		fake := &deadlineCommissioner{}
		sharedCommissioner = fake
		args := []string{"1", "3035-750-7966"}
		if cmd == pairingCodeWifiCmd {
			args = append(args, "fictional-network", "fictional-password")
		}
		before := time.Now()
		if err := cmd.RunE(cmd, args); err == nil {
			t.Fatal("synthetic failure hidden")
		}
		budget := fake.deadline.Sub(before)
		if budget < matter.DefaultCommissioningTimeout-time.Second || budget > matter.DefaultCommissioningTimeout+time.Second {
			t.Fatal("CLI did not allocate a full commissioning budget")
		}
	}
}
