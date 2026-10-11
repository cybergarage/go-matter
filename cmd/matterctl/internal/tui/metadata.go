// Copyright (C) 2026 The go-matter Authors. Licensed under the Apache License, Version 2.0.

package tui

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cybergarage/go-matter/matter/datamodel"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	"github.com/cybergarage/go-matter/matter/protocol/im"
)

// The offline dictionary never enables an operation or predicts device ACLs.
var dictionary, dictionaryError = datamodel.Load()

func clusterName(id im.ClusterID) string {
	if dictionary != nil {
		if c, ok := dictionary.Cluster(id); ok {
			return c.Name
		}
	}
	return "Unknown cluster"
}
func attributeDefinition(p Path) (datamodel.Attribute, bool) {
	if dictionary == nil {
		return datamodel.Attribute{}, false
	}
	if c, ok := dictionary.Cluster(p.Cluster); ok {
		if a, found := c.Attribute(p.Attribute); found {
			return a, true
		}
	}
	return dictionary.GlobalAttribute(p.Attribute)
}
func attributeName(p Path) string {
	if a, ok := attributeDefinition(p); ok {
		return a.Name
	}
	return "Unknown attribute"
}
func commandName(p Path) string {
	if dictionary != nil {
		if c, ok := dictionary.Cluster(p.Cluster); ok {
			if v, found := c.Command(p.Command, p.Direction); found {
				return v.Name
			}
		}
	}
	return "Unknown command"
}
func pathLabel(p Path) string {
	switch p.Kind {
	case "list":
		return fmt.Sprintf("EP %d / %s cluster list unavailable", p.Endpoint, p.Role)
	case "endpoint":
		return fmt.Sprintf("EP %d / DeviceTypeList", p.Endpoint)
	case "cluster":
		return fmt.Sprintf("EP %d / C 0x%08X / %s %s", p.Endpoint, p.Cluster, p.Role, clusterName(p.Cluster))
	case "command":
		return fmt.Sprintf("EP %d / C 0x%08X CMD 0x%08X / %s %s · %s", p.Endpoint, p.Cluster, p.Command, p.Direction, clusterName(p.Cluster), commandName(p))
	default:
		return fmt.Sprintf("EP %d / C 0x%08X A 0x%08X / %s · %s", p.Endpoint, p.Cluster, p.Attribute, clusterName(p.Cluster), attributeName(p))
	}
}
func pathDetail(p Path) string {
	text := pathLabel(p) + "\n"
	if p.Kind == "" {
		if a, ok := attributeDefinition(p); ok {
			text += fmt.Sprintf("Definition: type=%s nullable=%t writable=%t (metadata only)\n", a.Type, a.Nullable, a.Writable)
			if t, found := dictionary.Type(a.Type, p.Cluster); found {
				text += "Type metadata: " + t.Definition.Property("description") + "\n"
			}
			if unit := a.Definition.Property("unit"); unit != "" {
				text += "Defined unit: " + unit + "\n"
			} else {
				text += "Unit/scale: not declared in imported metadata; no conversion inferred.\n"
			}
		} else {
			text += "Definition unavailable; numeric IDs retained.\n"
		}
		text += "Value: NOT FETCHED for selected attribute. Use explicit Read; presence is not ACL permission.\n"
	}
	if dictionaryError != nil {
		text += "Definition DB unavailable. Numeric fallback only.\n"
	}
	text += p.Inventory + "\n"
	return text + "Partial SDK dictionary; conditions and access privileges are not evaluated."
}

// scalarValue retains a decoded raw value without manufacturing a unit or scale.
func scalarValue(e tlv.Element, p Path) (string, string, bool) {
	raw := e.String()
	value := ""
	switch {
	case e.Type() == tlv.Null:
		value = "null"
	default:
		if v, ok := e.Bool(); ok {
			value = fmt.Sprint(v)
		} else if v, ok := e.Signed(); ok {
			value = fmt.Sprint(v)
		} else if v, ok := e.Unsigned(); ok {
			value = fmt.Sprint(v)
		} else if v, ok := e.Float(); ok {
			value = fmt.Sprint(v)
		} else if v, ok := e.UTF8(); ok {
			value = strconv.Quote(v)
		} else if v, ok := e.Bytes(); ok {
			value = fmt.Sprintf("0x%X", v)
			raw = value
		}
	}
	if value == "" {
		return "UNSUPPORTED container/value (use list decoder when defined)", raw, false
	}
	if a, ok := attributeDefinition(p); ok {
		if t, found := dictionary.Type(a.Type, p.Cluster); found {
			if numeric, unsigned := e.Unsigned(); unsigned {
				for _, item := range t.Definition.NamedChildren("item") {
					v, err := strconv.ParseUint(item.Property("value"), 0, 64)
					if err == nil && v == numeric {
						value += " (" + item.Property("name") + ")"
					}
				}
			}
		}
	}
	return value, raw, true
}
func observationMessage(p Path, value, raw, status string, at time.Time) string {
	typ := "unknown definition"
	if a, ok := attributeDefinition(p); ok {
		typ = a.Type
		if unit := a.Definition.Property("unit"); unit != "" {
			value += " " + unit
		}
	}
	return fmt.Sprintf("%s\n%s\nType: %s\nValue: %s\nRaw decoded TLV value: %s\nReceived at: %s\nSession closed; no subscription. Presence does not grant ACL permission.", status, pathLabel(p), typ, value, raw, at.UTC().Format(time.RFC3339Nano))
}
func listValue(dec tlv.Decoder, e tlv.Element, depth int) (string, error) {
	if depth > 16 {
		return "", fmt.Errorf("value nesting exceeds display limit")
	}
	if e.Type() == tlv.Structure || e.Type() == tlv.Array || e.Type() == tlv.List {
		var values []string
		for dec.Next() {
			child := dec.Element()
			if child.Type().IsEndOfContainer() {
				return "[" + strings.Join(values, ", ") + "]", nil
			}
			v, err := listValue(dec, child, depth+1)
			if err != nil {
				return "", err
			}
			values = append(values, fmt.Sprintf("%s=%s", child.Tag(), v))
			if len(values) > 4096 {
				return "", fmt.Errorf("value exceeds display limit")
			}
		}
		if err := dec.Error(); err != nil {
			return "", err
		}
		return "", fmt.Errorf("unterminated container")
	}
	v, _, ok := scalarValue(e, Path{})
	if !ok {
		return "", fmt.Errorf("unsupported list value")
	}
	return v, nil
}

func statusLabel(s *im.InvokeStatus) string {
	label := "UNAVAILABLE"
	switch im.Status(s.IMStatus) {
	case im.StatusUnsupportedAttribute, im.StatusUnsupportedCluster, im.StatusUnsupportedEndpoint, im.StatusUnsupportedRead:
		label = "UNSUPPORTED"
	case im.StatusUnsupportedAccess:
		label = "ACCESS DENIED"
	}
	return fmt.Sprintf("%s: IM status 0x%02X / cluster status 0x%02X; no value", label, s.IMStatus, s.ClusterStatus)
}
