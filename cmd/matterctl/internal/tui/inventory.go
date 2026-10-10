// Copyright (C) 2026 The go-matter Authors. Licensed under the Apache License, Version 2.0.

package tui

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cybergarage/go-matter/matter"
	"github.com/cybergarage/go-matter/matter/cluster/descriptor"
	"github.com/cybergarage/go-matter/matter/protocol/im"
)

const serverRole = "server"
const clientRole = "client"

// A read-only seam for deterministic tests. No test starts a commissioner.
type inventoryReader interface {
	parts() ([]im.EndpointID, error)
	deviceTypes(im.EndpointID) ([]descriptor.DeviceType, error)
	clusters(im.EndpointID, bool) ([]im.ClusterID, error)
	ids(im.EndpointID, im.ClusterID, im.AttributeID) ([]uint32, error)
	scalar(im.EndpointID, im.ClusterID, im.AttributeID) (uint64, error)
}
type nodeInventoryReader struct{ matter.Node }

func (n nodeInventoryReader) parts() ([]im.EndpointID, error) {
	return descriptor.PartsList(n.Session(), 0)
}
func (n nodeInventoryReader) deviceTypes(ep im.EndpointID) ([]descriptor.DeviceType, error) {
	return descriptor.DeviceTypeList(n.Session(), ep)
}
func (n nodeInventoryReader) clusters(ep im.EndpointID, server bool) ([]im.ClusterID, error) {
	if server {
		return descriptor.ServerList(n.Session(), ep)
	}
	return descriptor.ClientList(n.Session(), ep)
}
func (n nodeInventoryReader) ids(ep im.EndpointID, cl im.ClusterID, a im.AttributeID) ([]uint32, error) {
	return listIDs(n.Node, ep, cl, a)
}
func (n nodeInventoryReader) scalar(ep im.EndpointID, cl im.ClusterID, a im.AttributeID) (uint64, error) {
	r, e := n.ReadAttribute(ep, cl, a)
	if e != nil || r == nil || r.Value == nil || r.Status != nil {
		return 0, errors.New("unavailable / read error")
	}
	v, ok := r.Value.Unsigned()
	if !ok {
		return 0, errors.New("unexpected TLV type")
	}
	return v, nil
}
func listState(name string, ids []uint32, err error) string {
	if err != nil {
		return name + ": UNAVAILABLE / ERROR; " + err.Error() + "; support and permission unknown"
	}
	return fmt.Sprintf("%s: OBSERVED %v (decoded raw numeric IDs)", name, ids)
}
func inspectInventory(n inventoryReader) (Result, error) {
	eps, err := n.parts()
	if err != nil {
		return Result{}, errors.New("descriptor PartsList UNAVAILABLE / ERROR; inventory unknown")
	}
	out := Result{Message: "OBSERVED inventory snapshot. Dictionary presence is not device support or ACL permission.\nValues are not monitored. Select a row for metadata or explicitly Read an attribute."}
	seen := map[im.EndpointID]bool{}
	for _, ep := range append([]im.EndpointID{0}, eps...) {
		if seen[ep] {
			continue
		}
		seen[ep] = true
		types, te := n.deviceTypes(ep)
		info := "DeviceTypeList: UNAVAILABLE / ERROR"
		if te == nil {
			var labels []string
			for _, dt := range types {
				name := "Unknown device type"
				rev := "definition unavailable"
				if dictionary != nil {
					if d, ok := dictionary.DeviceType(dt.DeviceType); ok {
						name = d.Name
						rev = fmt.Sprintf("dictionary revision %d", d.Revision)
						if d.Revision != dt.Revision {
							rev += " (REVISION MISMATCH)"
						}
					}
				}
				labels = append(labels, fmt.Sprintf("%s (0x%08X), observed revision %d / %s", name, dt.DeviceType, dt.Revision, rev))
			}
			info = "DeviceTypeList OBSERVED: " + strings.Join(labels, "; ")
		}
		info += "\nReceived at: " + time.Now().UTC().Format(time.RFC3339Nano)
		out.Paths = append(out.Paths, Path{Endpoint: ep, Kind: "endpoint", Inventory: info})
		for _, server := range []bool{true, false} {
			cls, ce := n.clusters(ep, server)
			role := clientRole
			if server {
				role = serverRole
			}
			if ce != nil {
				out.Paths = append(out.Paths, Path{Endpoint: ep, Kind: "list", Role: role, Inventory: info + "\n" + role + " list UNAVAILABLE / ERROR; no inferred clusters"})
				continue
			}
			for _, cl := range cls {
				p := Path{Endpoint: ep, Cluster: cl, Kind: "cluster", Role: role, Inventory: info + "\nOBSERVED in Descriptor " + role + " list."}
				if !server {
					out.Paths = append(out.Paths, p)
					continue
				}
				attrs, ae := n.ids(ep, cl, 0xFFFB)
				accepted, ace := n.ids(ep, cl, 0xFFF9)
				generated, gce := n.ids(ep, cl, 0xFFF8)
				feature, fe := n.scalar(ep, cl, 0xFFFC)
				revision, re := n.scalar(ep, cl, 0xFFFD)
				p.Inventory += "\n" + listState("AttributeList", attrs, ae) + "\n" + listState("AcceptedCommandList", accepted, ace) + "\n" + listState("GeneratedCommandList", generated, gce)
				if fe == nil && feature <= 0xFFFFFFFF {
					p.Inventory += fmt.Sprintf("\nFeatureMap OBSERVED: 0x%08X (raw %d)", feature, feature)
				} else {
					p.Inventory += "\nFeatureMap: UNAVAILABLE / ERROR"
				}
				if re == nil && revision <= 0xFFFF {
					p.Inventory += fmt.Sprintf("\nClusterRevision OBSERVED: %d", revision)
					if dictionary != nil {
						if d, ok := dictionary.Cluster(cl); ok {
							p.Inventory += fmt.Sprintf(" / dictionary %d", d.Revision)
							if uint64(d.Revision) != revision {
								p.Inventory += " (REVISION MISMATCH; conditions not inferred)"
							}
						}
					}
				} else {
					p.Inventory += "\nClusterRevision: UNAVAILABLE / ERROR"
				}
				p.Inventory += "\nInventory received at: " + time.Now().UTC().Format(time.RFC3339Nano)
				out.Paths = append(out.Paths, p)
				start := len(out.Paths)
				out.addInventory(ep, cl, attrs, ae, accepted, ace)
				for i := start; i < len(out.Paths); i++ {
					out.Paths[i].Inventory = p.Inventory
				}
				for _, group := range []struct {
					ids       []uint32
					err       error
					direction string
				}{{accepted, ace, clientRole}, {generated, gce, serverRole}} {
					if group.err != nil {
						continue
					}
					for _, id := range group.ids {
						out.Paths = append(out.Paths, Path{Endpoint: ep, Cluster: cl, Command: im.CommandID(id), Kind: "command", Direction: group.direction, Role: serverRole, Inventory: p.Inventory + "\nOBSERVED command ID; no ACL or invocation permission inferred."})
					}
				}
			}
		}
	}
	return out, nil
}

// simulatedInventory is fictional; it does not use a session, socket or credential.
type simulatedInventory struct{}

func (simulatedInventory) parts() ([]im.EndpointID, error) { return []im.EndpointID{1}, nil }
func (simulatedInventory) deviceTypes(ep im.EndpointID) ([]descriptor.DeviceType, error) {
	id := uint32(0x16)
	if ep == 1 {
		id = 0x100
	}
	return []descriptor.DeviceType{{DeviceType: id, Revision: 3}}, nil
}
func (simulatedInventory) clusters(ep im.EndpointID, server bool) ([]im.ClusterID, error) {
	if !server {
		return []im.ClusterID{0x9999}, nil
	}
	if ep == 0 {
		return []im.ClusterID{0x1D, 0x28}, nil
	}
	return []im.ClusterID{6, 0x402, 0xFFF10001}, nil
}
func (simulatedInventory) ids(_ im.EndpointID, cl im.ClusterID, a im.AttributeID) ([]uint32, error) {
	switch a {
	case 0xFFFB:
		switch cl {
		case 0x1D:
			return []uint32{0, 1, 2, 3, 0xFFFD}, nil
		case 0x28:
			return []uint32{1, 2, 3, 4, 7, 8, 0xFFFD}, nil
		case 6:
			return []uint32{0, 0x4003, 0xFFFC, 0xFFFD}, nil
		case 0x402:
			return []uint32{0, 1, 2}, nil
		default:
			return []uint32{0xABCD}, nil
		}
	case 0xFFF9:
		if cl == 6 {
			return []uint32{0, 1, 2, 0xFE}, nil
		}
	case 0xFFF8:
		if cl == 0xFFF10001 {
			return nil, errors.New("fictional denied list")
		}
	}
	return []uint32{}, nil
}
func (simulatedInventory) scalar(_ im.EndpointID, cl im.ClusterID, a im.AttributeID) (uint64, error) {
	if a == 0xFFFC {
		return 1, nil
	}
	switch cl {
	case 6:
		return 5, nil
	case 0x1D:
		return 3, nil
	case 0x28:
		return 6, nil
	case 0x402:
		return 4, nil
	default:
		return 99, nil
	}
}
