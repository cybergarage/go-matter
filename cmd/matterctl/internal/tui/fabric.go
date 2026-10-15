// Copyright (C) 2026 The go-matter Authors. Licensed under the Apache License, Version 2.0.

package tui

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/cybergarage/go-matter/matter"
	"github.com/cybergarage/go-matter/matter/credentials"
	"github.com/cybergarage/go-matter/matter/keystore"
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

// identityFromRecord returns the identity of r, with the keys of ks for the
// keys r does not hold.
func identityFromRecord(r store.FabricRecord, ks keystore.KeyStore) credentials.ControllerIdentity {
	id := credentials.ControllerIdentity{FabricID: r.FabricID, NodeID: r.AdminNodeID, RootCertificate: r.RootCertificate, RootPrivateKey: r.RootPrivateKey, NOC: r.NOC, PrivateKey: r.PrivateKey, IPK: r.IPK}
	if ks == nil {
		return id
	}
	if len(id.RootPrivateKey) == 0 {
		id.RootSigner, _ = ks.Signer(matter.RootKeyName)
	}
	if len(id.PrivateKey) == 0 {
		id.Signer, _ = ks.Signer(matter.OperationalKeyName)
	}
	return id
}
func validFabric(r store.FabricRecord, ks keystore.KeyStore) error {
	// The commissioner CA currently signs directly with the root; intermediate-backed bootstrap is unsupported.
	if r.AdminVendorID == 0 || r.AdminVendorID > 0xFFF4 || len(r.ICAC) != 0 {
		return errors.New("unsupported controller vendor or intermediate identity")
	}
	return credentials.ValidateControllerIdentity(identityFromRecord(r, ks))
}

// parseVendor reads a vendor ID in hexadecimal, as Matter writes them
// (2.5.2. Vendor Identifier), with or without 0x and surrounding spaces:
// "0xFFF1", "FFF1" and " fff1 " are all 0xFFF1. Decimal is not accepted,
// since "1234" could be either.
func parseVendor(s string) (uint16, error) {
	s = strings.TrimSpace(s)
	digits := strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	n, err := strconv.ParseUint(digits, 16, 16)
	if digits == "" || err != nil || n == 0 || n > 0xFFF4 {
		return 0, errors.New("enter a nonzero hexadecimal vendor ID (0x optional), such as your assigned one, or a Matter test vendor ID 0xFFF1–0xFFF4 for development")
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
