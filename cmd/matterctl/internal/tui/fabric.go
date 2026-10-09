// Copyright (C) 2026 The go-matter Authors. Licensed under the Apache License, Version 2.0.

package tui

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/cybergarage/go-matter/matter/credentials"
	"github.com/cybergarage/go-matter/matter/store"
)

type FabricSummary struct {
	Present, Valid                            bool
	FabricID, AdminNodeID, CompressedFabricID uint64
	VendorID                                  uint16
	Saved                                     int
}

func (s FabricSummary) String() string {
	if !s.Present {
		return "NO FABRIC — choose Create new fabric explicitly. No keys are generated at startup."
	}
	state := "VALIDATED (local only)"
	if !s.Valid {
		state = "INVALID / UNSUPPORTED — network actions blocked"
	}
	return fmt.Sprintf("Fabric %016X / compressed %016X\nController node %016X / vendor %04X\nSaved nodes: %d / %s\nSaved identity does not grant access to another controller's fabric.", s.FabricID, s.CompressedFabricID, s.AdminNodeID, s.VendorID, s.Saved, state)
}

// Optional interface keeps transport fixtures and consumers compatible.
type fabricBackend interface {
	Overview() (FabricSummary, error)
	CreateFabric(context.Context, uint16) (Result, error)
}

func identityFromRecord(r store.FabricRecord) credentials.ControllerIdentity {
	return credentials.ControllerIdentity{FabricID: r.FabricID, NodeID: r.AdminNodeID, RootCertificate: r.RootCertificate, RootPrivateKey: r.RootPrivateKey, NOC: r.NOC, PrivateKey: r.PrivateKey, IPK: r.IPK}
}
func validFabric(r store.FabricRecord) error {
	// The commissioner CA currently signs directly with the root; intermediate-backed bootstrap is unsupported.
	if r.AdminVendorID == 0 || r.AdminVendorID > 0xFFF4 || len(r.ICAC) != 0 {
		return errors.New("unsupported controller vendor or intermediate identity")
	}
	return credentials.ValidateControllerIdentity(identityFromRecord(r))
}
func parseVendor(s string) (uint16, error) {
	n, err := strconv.ParseUint(s, 0, 16)
	if err != nil || n == 0 || n > 0xFFF4 {
		return 0, errors.New("enter a nonzero assigned vendor ID, or a Matter test vendor ID (0xFFF1–0xFFF4) for development")
	}
	return uint16(n), nil
}
func (b *Demo) Overview() (FabricSummary, error) {
	ds, _ := b.List()
	return FabricSummary{Present: true, Valid: true, FabricID: 2, AdminNodeID: 1, VendorID: 0xFFF1, Saved: len(ds)}, nil
}
func (b *Demo) CreateFabric(context.Context, uint16) (Result, error) {
	return Result{}, errors.New("offline fixture already has a fictional fabric; no credentials can be generated")
}
