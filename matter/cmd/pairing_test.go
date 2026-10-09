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
	opts     []matter.CommissionOption
}

func (c *deadlineCommissioner) Commission(ctx context.Context, _ matter.OnboardingPayload, opts ...matter.CommissionOption) (matter.Commissionee, error) {
	c.deadline, _ = ctx.Deadline()
	c.opts = opts
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

func TestPairingCLIHonorsNodeArgument(t *testing.T) {
	prev := sharedCommissioner
	t.Cleanup(func() { sharedCommissioner = prev })
	for _, command := range []*cobra.Command{pairingCodeCmd, pairingCodeWifiCmd} {
		for _, input := range []string{"42", "0x2A", "auto", "0", "-1", "18446744073709551615", "not-an-id"} {
			fake := &deadlineCommissioner{}
			sharedCommissioner = fake
			args := []string{input, "3035-750-7966"}
			if command == pairingCodeWifiCmd {
				args = append(args, "fictional", "fictional")
			}
			_ = command.RunE(command, args)
			valid := input == "42" || input == "0x2A" || input == "auto"
			if valid {
				found := false
				for _, opt := range fake.opts {
					if id, ok := opt.(matter.CommissionNodeID); ok {
						found = true
						want := uint64(42)
						if input == "auto" {
							want = 0
						}
						if uint64(id) != want {
							t.Fatal("node ID not forwarded")
						}
					}
				}
				if !found {
					t.Fatal("node option missing")
				}
			} else if !fake.deadline.IsZero() {
				t.Fatal("invalid input reached commissioning")
			}
		}
	}
}
