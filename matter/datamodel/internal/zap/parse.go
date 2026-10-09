// Copyright (C) 2026 The go-matter Authors. Licensed under the Apache License, Version 2.0.

// Package zap reads the audited SDK XML subset without inventing unsupported semantics.
package zap

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/cybergarage/go-matter/matter/datamodel"
	"github.com/cybergarage/go-matter/matter/protocol/im"
)

// Names/attributes audited in the pinned seven-file input set. Preserve the full
// metadata tree; future schema requires review, not an automatic interpretation.
const tags = "access accessControl andTerm arg atomic attribute bitmap class client cluster clusters code command compositionType condition configurator define description deviceId deviceType disallowConform domain endpoint endpointComposition enum event feature features field global globalAttribute include item mandatoryConform modifier name notTerm operation optionalConform orTerm otherwiseConform profileId provisionalConform requireAttribute requireCommand requireEvent revision role scope server struct superset tag type typeName"
const attrs = "analog apiMaturity array bit client clientLocked cluster code composite conformance constraint default define description disableDefaultResponse discrete editable entryType fieldId id init isNullable length lockOthers mask max min minLength mustUseTimedInvoke name op optional priority privilege response role server serverLocked side signed size source summary tick type value writable"

func known(list, name string) bool { return strings.Contains(" "+list+" ", " "+name+" ") }
func Parse(r io.Reader) (datamodel.Element, error) {
	dec := xml.NewDecoder(r)
	var stack []*datamodel.Element
	var root *datamodel.Element
	for {
		token, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return datamodel.Element{}, err
		}
		switch t := token.(type) {
		case xml.StartElement:
			if t.Name.Space != "" || !known(tags, t.Name.Local) {
				return datamodel.Element{}, fmt.Errorf("unsupported XML element %s", t.Name.Local)
			}
			e := &datamodel.Element{Name: t.Name.Local}
			seen := map[string]bool{}
			for _, a := range t.Attr {
				key := a.Name.Space + "/" + a.Name.Local
				if seen[key] {
					return datamodel.Element{}, errors.New("duplicate XML property")
				}
				seen[key] = true
				// XML namespace/schema declarations are retained, not interpreted.
				schema := a.Name.Space == "xmlns" || a.Name.Local == "xmlns" || (a.Name.Space == "http://www.w3.org/2001/XMLSchema-instance" && a.Name.Local == "noNamespaceSchemaLocation")
				if !schema && (a.Name.Space != "" || !known(attrs, a.Name.Local)) {
					return datamodel.Element{}, fmt.Errorf("unsupported XML property %s", a.Name.Local)
				}
				e.Attributes = append(e.Attributes, datamodel.XMLAttribute{Name: a.Name.Local, Namespace: a.Name.Space, Value: a.Value})
			}
			if len(stack) == 0 {
				if root != nil {
					return datamodel.Element{}, errors.New("multiple XML roots")
				}
				root = e
			}
			stack = append(stack, e)
		case xml.EndElement:
			e := stack[len(stack)-1]
			e.Text = strings.TrimSpace(e.Text)
			stack = stack[:len(stack)-1]
			if len(stack) > 0 {
				parent := stack[len(stack)-1]
				parent.Children = append(parent.Children, *e)
			}
		case xml.CharData:
			if len(stack) > 0 {
				stack[len(stack)-1].Text += string(t)
			} else if strings.TrimSpace(string(t)) != "" {
				return datamodel.Element{}, errors.New("text outside XML root")
			}
		case xml.ProcInst:
			if t.Target != "xml" {
				return datamodel.Element{}, errors.New("XML processing instructions are unsupported")
			}
		case xml.Directive:
			return datamodel.Element{}, errors.New("XML directives are unsupported")
		}
	}
	if root == nil || len(stack) != 0 || root.Name != "configurator" {
		return datamodel.Element{}, errors.New("expected SDK configurator root")
	}
	return *root, nil
}
func number(s string, bits int) (uint64, error) {
	base := 10
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		base = 16
		s = s[2:]
	}
	v, err := strconv.ParseUint(s, base, bits)
	if err != nil {
		return 0, errors.New("invalid numeric identity or revision")
	}
	return v, nil
}
func boolProperty(e datamodel.Element, key string) (bool, error) {
	v := e.Property(key)
	switch v {
	case "", "false":
		return false, nil
	case "true":
		return true, nil
	default:
		return false, fmt.Errorf("unsupported %s value", key)
	}
}
func attr(e datamodel.Element) (datamodel.Attribute, error) {
	id, err := number(e.Property("code"), 32)
	if err != nil {
		return datamodel.Attribute{}, err
	}
	writable, err := boolProperty(e, "writable")
	if err != nil {
		return datamodel.Attribute{}, err
	}
	nullable, err := boolProperty(e, "isNullable")
	if err != nil {
		return datamodel.Attribute{}, err
	}
	name := e.Property("name")
	if name == "" {
		name = e.Text
	}
	if name == "" || e.Property("type") == "" {
		return datamodel.Attribute{}, errors.New("attribute name/type missing")
	}
	return datamodel.Attribute{ID: im.AttributeID(id), Name: name, Type: e.Property("type"), Writable: writable, Nullable: nullable, Definition: e}, nil
}

// AddDocument indexes core IDs/types and keeps all source metadata. Cross-cluster
// references are deliberately unresolved in this partial catalog.
func AddDocument(c *datamodel.Catalog, file string, root datamodel.Element) error {
	c.Documents = append(c.Documents, datamodel.Document{File: file, Root: root})
	for _, e := range root.Children {
		switch e.Name {
		case "cluster":
			code, ok := e.Child("code")
			if !ok {
				return errors.New("cluster code missing")
			}
			id, err := number(code.Text, 32)
			if err != nil {
				return err
			}
			name, _ := e.Child("name")
			if name.Text == "" {
				return errors.New("cluster name missing")
			}
			cluster := datamodel.Cluster{ID: im.ClusterID(id), Name: name.Text, Source: file, Definition: e}
			for _, child := range e.Children {
				switch child.Name {
				case "globalAttribute":
					if child.Property("code") == "0xFFFD" {
						rev, err := number(child.Property("value"), 16)
						if err != nil {
							return err
						}
						cluster.Revision = uint16(rev)
					}
				case "attribute":
					a, err := attr(child)
					if err != nil {
						return err
					}
					cluster.Attributes = append(cluster.Attributes, a)
				case "command":
					id, err := number(child.Property("code"), 32)
					if err != nil {
						return err
					}
					timed, err := boolProperty(child, "mustUseTimedInvoke")
					if err != nil {
						return err
					}
					source := child.Property("source")
					if source != "client" && source != "server" {
						return errors.New("unsupported command direction")
					}
					cluster.Commands = append(cluster.Commands, datamodel.Command{ID: im.CommandID(id), Name: child.Property("name"), Source: source, Timed: timed, Definition: child})
				}
			}
			c.Clusters = append(c.Clusters, cluster)
		case "deviceType":
			code, ok := e.Child("deviceId")
			if !ok {
				return errors.New("device ID missing")
			}
			id, err := number(code.Text, 32)
			if err != nil {
				return err
			}
			name, _ := e.Child("typeName")
			if name.Text == "" {
				return errors.New("device type name missing")
			}
			rev := uint64(0)
			if r, ok := e.Child("revision"); ok {
				rev, err = number(r.Text, 16)
				if err != nil {
					return err
				}
			}
			c.DeviceTypes = append(c.DeviceTypes, datamodel.DeviceType{ID: uint32(id), Name: name.Text, Revision: uint16(rev), VendorSpecific: id > 0xFFFF, Definition: e})
		case "global":
			for _, a := range e.NamedChildren("attribute") {
				v, err := attr(a)
				if err != nil {
					return err
				}
				c.Globals = append(c.Globals, v)
			}
		case "atomic":
			for _, t := range e.NamedChildren("type") {
				c.Types = append(c.Types, datamodel.TypeDefinition{Name: t.Property("name"), Kind: "atomic", Source: file, Definition: t})
			}
		case "enum", "bitmap", "struct":
			typ := datamodel.TypeDefinition{Name: e.Property("name"), Kind: e.Name, Source: file, Definition: e}
			for _, cl := range e.NamedChildren("cluster") {
				id, err := number(cl.Property("code"), 32)
				if err != nil {
					return err
				}
				typ.Clusters = append(typ.Clusters, im.ClusterID(id))
			}
			c.Types = append(c.Types, typ)
		}
	}
	return nil
}

// Validate rejects ambiguous normalized lookups instead of selecting arbitrary definitions.
func Validate(c *datamodel.Catalog) error {
	globals := map[im.AttributeID]bool{}
	for _, a := range c.Globals {
		if globals[a.ID] {
			return errors.New("duplicate global attribute ID")
		}
		globals[a.ID] = true
	}
	clusters := map[im.ClusterID]bool{}
	devices := map[uint32]bool{}
	for _, cl := range c.Clusters {
		if clusters[cl.ID] {
			return errors.New("duplicate cluster ID")
		}
		clusters[cl.ID] = true
		attrs := map[im.AttributeID]bool{}
		commands := map[string]bool{}
		for _, a := range cl.Attributes {
			if attrs[a.ID] {
				return errors.New("duplicate attribute ID")
			}
			attrs[a.ID] = true
		}
		for _, command := range cl.Commands {
			key := fmt.Sprintf("%d/%s", command.ID, command.Source)
			if commands[key] {
				return errors.New("duplicate command ID/direction")
			}
			commands[key] = true
		}
	}
	for _, dt := range c.DeviceTypes {
		if devices[dt.ID] {
			return errors.New("duplicate device type ID")
		}
		devices[dt.ID] = true
	}
	types := map[string]bool{}
	for _, t := range c.Types {
		scopes := t.Clusters
		if len(scopes) == 0 {
			scopes = []im.ClusterID{0xFFFFFFFF}
		}
		for _, id := range scopes {
			key := fmt.Sprintf("%s/%d", t.Name, id)
			if types[key] {
				return errors.New("duplicate type name/scope")
			}
			types[key] = true
		}
	}
	sort.Slice(c.Clusters, func(i, j int) bool { return c.Clusters[i].ID < c.Clusters[j].ID })
	sort.Slice(c.DeviceTypes, func(i, j int) bool { return c.DeviceTypes[i].ID < c.DeviceTypes[j].ID })
	return nil
}
